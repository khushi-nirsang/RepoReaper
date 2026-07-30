// Package content safely expands text encodings and common archive formats for
// secret detection. It never writes extracted material to disk.
package content

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// SemanticsVersion changes whenever expansion behavior or its default limits
// change in a way that can affect detector results. Persistent scan caches bind
// their entries to this value so old expansion results are never reused under
// new semantics.
const SemanticsVersion = "content-expansion-v3"

type Limits struct {
	MaxUnitSize      int64
	MaxExpandedBytes int64
	MaxEntries       int
	MaxDepth         int
	MaxCompression   float64
}

type Unit struct {
	Data       []byte
	Location   string
	Decoder    string
	SourceLine int
}

type Result struct {
	Units           []Unit
	Warnings        []string
	ArchivesOpened  int
	EncodedPayloads int
	BytesInspected  int64
}

var base64Candidate = regexp.MustCompile(`(?:^|[^A-Za-z0-9_+/\-])([A-Za-z0-9_+/\-]{32,}={0,2})(?:$|[^A-Za-z0-9_+/=-])`)

func Expand(input []byte, limits Limits) Result {
	limits = normalizedLimits(limits)
	expander := &expander{limits: limits, warnings: map[string]bool{}}
	expander.walk(input, "", "", 0, 0, false)
	for warning := range expander.warnings {
		expander.result.Warnings = append(expander.result.Warnings, warning)
	}
	sortStrings(expander.result.Warnings)
	return expander.result
}

type expander struct {
	limits   Limits
	result   Result
	expanded int64
	entries  int
	warnings map[string]bool
}

func (e *expander) walk(data []byte, location, decoder string, depth, sourceLine int, expanded bool) {
	if depth > e.limits.MaxDepth {
		e.warn("nested content expansion depth limit reached")
		return
	}
	if int64(len(data)) > e.limits.MaxUnitSize {
		e.warn("embedded content exceeded the per-item size limit")
		return
	}
	if expanded {
		if int64(len(data)) > e.limits.MaxExpandedBytes-e.expanded {
			e.warn("embedded content expansion byte limit reached")
			return
		}
		e.expanded += int64(len(data))
	}

	switch {
	case isZIP(data):
		e.expandZIP(data, location, decoder, depth)
		return
	case isGzip(data):
		e.expandGzip(data, location, decoder, depth)
		return
	case isTar(data):
		e.expandTar(data, location, decoder, depth)
		return
	}
	text, textDecoder, textOK := normalizeText(data, e.limits.MaxUnitSize)
	if !textOK {
		if textDecoder != "" {
			e.warn("one or more UTF-16 text payloads could not be decoded")
		}
		return
	}
	if textDecoder != "" {
		decoder = appendDecoder(decoder, textDecoder)
	}
	e.result.Units = append(e.result.Units, Unit{Data: text, Location: location, Decoder: decoder, SourceLine: sourceLine})
	e.result.BytesInspected += int64(len(text))
	if depth < e.limits.MaxDepth {
		e.expandBase64(text, location, decoder, depth)
	}
}

func (e *expander) expandZIP(data []byte, location, decoder string, depth int) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		e.warn("one or more archives could not be inspected")
		return
	}
	e.result.ArchivesOpened++
	for _, file := range reader.File {
		if !e.nextEntry() {
			return
		}
		member := safeMemberName(file.Name)
		if member == "" {
			e.warn("an unsafe archive member path was skipped")
			continue
		}
		if file.FileInfo().IsDir() || file.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if file.UncompressedSize64 > uint64(e.limits.MaxUnitSize) {
			e.warn("an archive member exceeded the per-item size limit")
			continue
		}
		if file.CompressedSize64 > 0 && float64(file.UncompressedSize64)/float64(file.CompressedSize64) > e.limits.MaxCompression {
			e.warn("a high compression-ratio archive member was skipped")
			continue
		}
		entry, err := file.Open()
		if err != nil {
			e.warn("one or more archive members could not be inspected")
			continue
		}
		body, readErr := readBounded(entry, e.limits.MaxUnitSize)
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil {
			e.warn("one or more archive members could not be inspected")
			continue
		}
		e.walk(body, joinLocation(location, member), appendDecoder(decoder, "zip"), depth+1, 0, true)
	}
}

func (e *expander) expandGzip(data []byte, location, decoder string, depth int) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		e.warn("one or more gzip streams could not be inspected")
		return
	}
	e.result.ArchivesOpened++
	body, readErr := readBounded(reader, e.limits.MaxUnitSize)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		e.warn("one or more gzip streams could not be inspected")
		return
	}
	if len(data) > 0 && float64(len(body))/float64(len(data)) > e.limits.MaxCompression {
		e.warn("a high compression-ratio gzip stream was skipped")
		return
	}
	member := safeMemberName(reader.Name)
	if member == "" {
		member = "gzip-content"
	}
	e.walk(body, joinLocation(location, member), appendDecoder(decoder, "gzip"), depth+1, 0, true)
}

func (e *expander) expandTar(data []byte, location, decoder string, depth int) {
	reader := tar.NewReader(bytes.NewReader(data))
	e.result.ArchivesOpened++
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			e.warn("one or more tar archives could not be inspected")
			return
		}
		if !e.nextEntry() {
			return
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		member := safeMemberName(header.Name)
		if member == "" {
			e.warn("an unsafe archive member path was skipped")
			continue
		}
		if header.Size < 0 || header.Size > e.limits.MaxUnitSize {
			e.warn("an archive member exceeded the per-item size limit")
			continue
		}
		body, err := readBounded(reader, e.limits.MaxUnitSize)
		if err != nil {
			e.warn("one or more archive members could not be inspected")
			continue
		}
		e.walk(body, joinLocation(location, member), appendDecoder(decoder, "tar"), depth+1, 0, true)
	}
}

func (e *expander) expandBase64(data []byte, location, decoder string, depth int) {
	for _, indexes := range base64Candidate.FindAllSubmatchIndex(data, -1) {
		if len(indexes) < 4 || indexes[2] < 0 || indexes[3] <= indexes[2] {
			continue
		}
		candidate := data[indexes[2]:indexes[3]]
		remaining := e.limits.MaxExpandedBytes - e.expanded
		maxDecoded := min(e.limits.MaxUnitSize, remaining)
		// DecodedLen is an upper bound of at most two bytes above the
		// actual padded length. Reject before allocation when the decoded
		// payload cannot fit either the per-unit or remaining total budget.
		if maxDecoded < 1 || int64(base64.StdEncoding.DecodedLen(len(candidate))) > maxDecoded+2 {
			e.warn("a Base64 payload exceeded the decoded-content size limit")
			continue
		}
		decoded, ok := decodeBase64(candidate)
		if !ok || len(decoded) < 16 || (!isText(decoded) && !isUTF16Candidate(decoded) && !isArchive(decoded)) {
			continue
		}
		e.result.EncodedPayloads++
		e.walk(decoded, location, appendDecoder(decoder, "base64"), depth+1, lineNumber(data, indexes[2]), true)
	}
}

func (e *expander) nextEntry() bool {
	if e.entries >= e.limits.MaxEntries {
		e.warn("archive entry limit reached")
		return false
	}
	e.entries++
	return true
}

func (e *expander) warn(message string) {
	e.warnings[message] = true
}

func normalizedLimits(limits Limits) Limits {
	if limits.MaxUnitSize < 1 {
		limits.MaxUnitSize = 5 * 1024 * 1024
	}
	if limits.MaxExpandedBytes < limits.MaxUnitSize {
		if limits.MaxUnitSize > 32*1024*1024 {
			limits.MaxExpandedBytes = 256 * 1024 * 1024
		} else {
			limits.MaxExpandedBytes = limits.MaxUnitSize * 8
		}
	}
	if limits.MaxExpandedBytes > 256*1024*1024 {
		limits.MaxExpandedBytes = 256 * 1024 * 1024
	}
	if limits.MaxEntries < 1 {
		limits.MaxEntries = 1000
	}
	if limits.MaxDepth < 1 {
		limits.MaxDepth = 2
	}
	if limits.MaxDepth > 4 {
		limits.MaxDepth = 4
	}
	if limits.MaxCompression < 1 {
		limits.MaxCompression = 200
	}
	return limits
}

func readBounded(reader io.Reader, maxSize int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, ErrLimit
	}
	return body, nil
}

var ErrLimit = &limitError{}

type limitError struct{}

func (*limitError) Error() string { return "expanded content exceeds limit" }

func decodeBase64(candidate []byte) ([]byte, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		dst := make([]byte, encoding.DecodedLen(len(candidate)))
		n, err := encoding.Decode(dst, candidate)
		if err == nil {
			return dst[:n], true
		}
	}
	return nil, false
}

func isText(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return false
	}
	if len(data) == 0 {
		return true
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) || b >= 0x80 {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.85
}

// normalizeText accepts ordinary UTF-8 plus UTF-16LE/BE text with a BOM or a
// conservative BOM-less ASCII-shaped byte pattern. UTF-16 is decoded in
// memory under the same per-unit bound before detectors see it.
func normalizeText(data []byte, maxSize int64) ([]byte, string, bool) {
	if isText(data) {
		return data, "", true
	}
	order, decoder, recognized := utf16Order(data)
	if !recognized {
		return nil, "", false
	}
	decoded, ok := decodeUTF16(data, order, maxSize)
	if !ok || !isText(decoded) {
		return nil, decoder, false
	}
	return decoded, decoder, true
}

func isUTF16Candidate(data []byte) bool {
	_, _, recognized := utf16Order(data)
	return recognized
}

func utf16Order(data []byte) (binary.ByteOrder, string, bool) {
	if len(data) >= 2 {
		switch {
		case data[0] == 0xff && data[1] == 0xfe:
			return binary.LittleEndian, "utf-16le", true
		case data[0] == 0xfe && data[1] == 0xff:
			return binary.BigEndian, "utf-16be", true
		}
	}
	if len(data) < 8 || len(data)%2 != 0 {
		return nil, "", false
	}
	units := len(data) / 2
	if units > 4096 {
		units = 4096
	}
	var evenZero, oddZero int
	for index := 0; index < units; index++ {
		if data[index*2] == 0 {
			evenZero++
		}
		if data[index*2+1] == 0 {
			oddZero++
		}
	}
	if oddZero*100 >= units*60 && evenZero*100 <= units*10 {
		return binary.LittleEndian, "utf-16le", true
	}
	if evenZero*100 >= units*60 && oddZero*100 <= units*10 {
		return binary.BigEndian, "utf-16be", true
	}
	return nil, "", false
}

func decodeUTF16(data []byte, order binary.ByteOrder, maxSize int64) ([]byte, bool) {
	offset := 0
	if len(data) >= 2 && ((data[0] == 0xff && data[1] == 0xfe) || (data[0] == 0xfe && data[1] == 0xff)) {
		offset = 2
	}
	if (len(data)-offset)%2 != 0 || maxSize < 1 {
		return nil, false
	}
	capacity := len(data) - offset
	if int64(capacity) > maxSize {
		capacity = int(maxSize)
	}
	decoded := make([]byte, 0, capacity)
	for index := offset; index < len(data); index += 2 {
		first := order.Uint16(data[index : index+2])
		runeValue := rune(first)
		if utf16.IsSurrogate(runeValue) {
			if first >= 0xdc00 || index+3 >= len(data) {
				return nil, false
			}
			second := order.Uint16(data[index+2 : index+4])
			if second < 0xdc00 || second > 0xdfff {
				return nil, false
			}
			runeValue = utf16.DecodeRune(runeValue, rune(second))
			index += 2
		}
		if runeValue == 0 || !unicode.IsGraphic(runeValue) && runeValue != '\n' && runeValue != '\r' && runeValue != '\t' {
			return nil, false
		}
		runeBytes := utf8.RuneLen(runeValue)
		if runeBytes < 1 || int64(len(decoded)+runeBytes) > maxSize {
			return nil, false
		}
		decoded = utf8.AppendRune(decoded, runeValue)
	}
	return decoded, true
}

func isArchive(data []byte) bool { return isZIP(data) || isGzip(data) || isTar(data) }

func isZIP(data []byte) bool {
	return len(data) >= 4 && (bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) || bytes.Equal(data[:4], []byte{'P', 'K', 5, 6}) || bytes.Equal(data[:4], []byte{'P', 'K', 7, 8}))
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func isTar(data []byte) bool {
	return len(data) >= 265 && (bytes.Equal(data[257:262], []byte("ustar")) || bytes.Equal(data[257:265], []byte("ustar  \x00")))
}

func safeMemberName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == "" || path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

func joinLocation(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "!" + child
}

func appendDecoder(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "+" + next
}

func lineNumber(data []byte, index int) int {
	return bytes.Count(data[:index], []byte{'\n'}) + 1
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
