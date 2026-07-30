package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	contentx "github.com/khushi/reporeaper/internal/content"
	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
)

const (
	blobCacheMagic   = "RepoReaper blob scan cache v1\n"
	blobCacheFormat  = "reporeaper-blob-scan-cache"
	blobCacheVersion = 1

	defaultBlobCacheMaxEntries = 50_000
	defaultBlobCacheMaxBytes   = int64(64 * 1024 * 1024)
)

var (
	errCacheForeign = errors.New("path does not contain a RepoReaper blob cache")
	errCacheBusy    = errors.New("blob cache is locked by another process")
	errCacheCorrupt = errors.New("blob cache is corrupt")
	errCachePath    = errors.New("blob cache path is outside its trusted directory or traverses a link")
)

// CacheOptions configures the optional persistent cache used for immutable Git
// blobs. The path is intentionally excluded from reports because it can reveal
// local filesystem details.
type CacheOptions struct {
	Enabled    bool
	Path       string
	MaxEntries int
	MaxBytes   int64
}

type blobCacheFile struct {
	Format    string                    `json:"format"`
	Version   int                       `json:"version"`
	Semantics string                    `json:"semantics"`
	WrittenAt time.Time                 `json:"written_at"`
	Entries   map[string]blobCacheEntry `json:"entries"`
}

type blobCacheEntry struct {
	OID             string        `json:"oid"`
	Matches         []cachedMatch `json:"matches,omitempty"`
	Warnings        []string      `json:"warnings,omitempty"`
	Payloads        int           `json:"payloads"`
	Archives        int           `json:"archives"`
	EncodedPayloads int           `json:"encoded_payloads"`
	BytesInspected  int64         `json:"bytes_inspected"`
	LFS             bool          `json:"lfs"`
	LastUsedUnix    int64         `json:"last_used_unix"`
	Checksum        string        `json:"checksum"`
}

type cachedMatch struct {
	DetectorID  string           `json:"detector_id"`
	Redacted    string           `json:"redacted"`
	Fingerprint string           `json:"fingerprint"`
	Short       string           `json:"short_fingerprint"`
	ValueLength int              `json:"value_length"`
	Line        int              `json:"line"`
	Confidence  model.Confidence `json:"confidence"`
	Location    string           `json:"location,omitempty"`
	Decoder     string           `json:"decoder,omitempty"`
}

type blobCache struct {
	root       string
	path       string
	semantics  string
	maxEntries int
	maxBytes   int64
	active     map[string]bool
	entries    map[string]blobCacheEntry
	dirty      bool
	writable   bool
}

func cacheSemantics(detectors []detector.Detector, maxFileSize int64) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(
		hash,
		"reporeaper-blob-cache-semantics-v2\x00%s\x00%s\x00%d\x00",
		contentx.SemanticsVersion,
		detector.ResultSemanticsVersion,
		maxFileSize,
	)
	for index, active := range detectors {
		_, _ = fmt.Fprintf(hash, "%d\x00%s\x00%s\x00", index, active.ID(), active.Signature())
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func openBlobCache(root, path, semantics string, detectors []detector.Detector, maxEntries int, maxBytes int64) (*blobCache, []string) {
	if maxEntries < 1 {
		maxEntries = defaultBlobCacheMaxEntries
	}
	if maxBytes < 1 {
		maxBytes = defaultBlobCacheMaxBytes
	}
	cache := &blobCache{
		root: root, path: path, semantics: semantics, maxEntries: maxEntries, maxBytes: maxBytes,
		active: map[string]bool{}, entries: map[string]blobCacheEntry{}, writable: true,
	}
	if err := validateBlobCachePath(root, path); err != nil {
		cache.writable = false
		return cache, []string{"persistent blob scan cache path was outside its dedicated directory or traversed a link; cache use was disabled"}
	}
	for _, active := range detectors {
		cache.active[active.ID()] = true
	}
	loaded, status, err := readBlobCache(path, semantics, cache.active, maxEntries, maxBytes)
	switch {
	case err == nil:
		cache.entries = loaded
	case errors.Is(err, os.ErrNotExist):
		// A missing cache is the normal first-run state.
	case errors.Is(err, errCacheForeign):
		cache.writable = false
		return cache, []string{"persistent blob scan cache path contains an unrecognized file; cache use was disabled"}
	case errors.Is(err, errCacheCorrupt):
		return cache, []string{"persistent blob scan cache was invalid or corrupt; affected Git blobs will be rescanned"}
	default:
		return cache, []string{"persistent blob scan cache could not be read; affected Git blobs will be rescanned"}
	}
	if status == cacheStatusIncompatible {
		cache.entries = map[string]blobCacheEntry{}
	}
	if status == cacheStatusCorrupt {
		return cache, []string{"persistent blob scan cache contained invalid entries; affected Git blobs will be rescanned"}
	}
	return cache, nil
}

func (c *blobCache) get(oid string) (contentScanResult, bool, bool) {
	entry, ok := c.entries[oid]
	if !ok {
		return contentScanResult{}, false, false
	}
	entry.LastUsedUnix = time.Now().Unix()
	entry.Checksum = blobCacheEntryChecksum(entry)
	c.entries[oid] = entry
	c.dirty = true
	result := contentScanResult{
		warnings: append([]string{}, entry.Warnings...),
		payloads: entry.Payloads, archives: entry.Archives,
		encodedPayloads: entry.EncodedPayloads, bytesInspected: entry.BytesInspected,
	}
	for _, match := range entry.Matches {
		result.matches = append(result.matches, detector.Match{
			DetectorID: match.DetectorID, Redacted: match.Redacted,
			Fingerprint: match.Fingerprint, Short: match.Short, Line: match.Line,
			ValueLength: match.ValueLength, Confidence: match.Confidence,
			Location: match.Location, Decoder: match.Decoder,
		})
	}
	return result, entry.LFS, true
}

func (c *blobCache) put(oid string, result contentScanResult, lfs bool) bool {
	sanitized, scrubber, safe := detector.SanitizeMatches(result.matches)
	if !safe && len(result.matches) > 0 {
		return false
	}
	entry := blobCacheEntry{
		OID: oid, Warnings: make([]string, len(result.warnings)),
		Payloads: result.payloads, Archives: result.archives,
		EncodedPayloads: result.encodedPayloads, BytesInspected: result.bytesInspected,
		LFS: lfs, LastUsedUnix: time.Now().Unix(),
	}
	for index, warning := range result.warnings {
		entry.Warnings[index] = scrubber.Scrub(warning)
	}
	for _, match := range sanitized {
		full, short := fingerprint.SHA256(match.Value)
		if match.Value == "" || full != match.Fingerprint || short != match.Short ||
			match.ValueLength != len(match.Value) || match.Redacted == "" ||
			scrubber.Contains(match.DetectorID) || scrubber.Contains(match.Redacted) ||
			scrubber.Contains(match.Location) || scrubber.Contains(match.Decoder) {
			return false
		}
		entry.Matches = append(entry.Matches, cachedMatch{
			DetectorID: match.DetectorID, Redacted: match.Redacted,
			Fingerprint: match.Fingerprint, Short: match.Short, ValueLength: match.ValueLength,
			Line: match.Line, Confidence: match.Confidence,
			Location: match.Location, Decoder: match.Decoder,
		})
	}
	entry.Checksum = blobCacheEntryChecksum(entry)
	if !validGitOID(oid) || !validBlobCacheEntry(entry, c.active) {
		return false
	}
	c.entries[oid] = entry
	c.dirty = true
	return true
}

func (c *blobCache) save() error {
	if !c.dirty || !c.writable {
		return nil
	}
	if err := validateBlobCachePath(c.root, c.path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil {
		return err
	}
	if err := validateBlobCachePath(c.root, c.path); err != nil {
		return err
	}
	unlock, err := acquireBlobCacheLock(c.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	// Merge a snapshot written after this process opened the cache. Entries are
	// immutable scan results; the newest access timestamp wins.
	if err := validateBlobCachePath(c.root, c.path); err != nil {
		return err
	}
	current, status, readErr := readBlobCache(c.path, c.semantics, c.active, c.maxEntries, c.maxBytes)
	switch {
	case readErr == nil && status == cacheStatusOK:
		for oid, entry := range current {
			ours, exists := c.entries[oid]
			if !exists || entry.LastUsedUnix > ours.LastUsedUnix {
				c.entries[oid] = entry
			}
		}
	case errors.Is(readErr, os.ErrNotExist), errors.Is(readErr, errCacheCorrupt):
	case errors.Is(readErr, errCacheForeign):
		return readErr
	case readErr != nil:
		return readErr
	}

	body, retained, err := marshalBoundedBlobCache(c.semantics, c.entries, c.maxEntries, c.maxBytes)
	if err != nil {
		return err
	}
	if err := writeBlobCacheAtomic(c.root, c.path, body); err != nil {
		return err
	}
	c.entries = retained
	c.dirty = false
	return nil
}

type cacheReadStatus int

const (
	cacheStatusOK cacheReadStatus = iota
	cacheStatusIncompatible
	cacheStatusCorrupt
)

func readBlobCache(path, semantics string, active map[string]bool, maxEntries int, maxBytes int64) (map[string]blobCacheEntry, cacheReadStatus, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, cacheStatusOK, err
	}
	if cachePathComponentUnsafe(info) || !info.Mode().IsRegular() {
		return nil, cacheStatusOK, errCacheForeign
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, cacheStatusOK, fmt.Errorf("%w: cache permissions are not owner-only", errCacheCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, cacheStatusOK, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, cacheStatusOK, err
	}
	if !bytes.HasPrefix(data, []byte(blobCacheMagic)) {
		return nil, cacheStatusOK, errCacheForeign
	}
	if int64(len(data)) > maxBytes {
		return nil, cacheStatusOK, fmt.Errorf("%w: cache exceeds configured byte limit", errCacheCorrupt)
	}
	var disk blobCacheFile
	if err := json.Unmarshal(data[len(blobCacheMagic):], &disk); err != nil {
		return nil, cacheStatusOK, fmt.Errorf("%w: %v", errCacheCorrupt, err)
	}
	if disk.Format != blobCacheFormat || disk.Version != blobCacheVersion {
		return map[string]blobCacheEntry{}, cacheStatusCorrupt, nil
	}
	if disk.Semantics != semantics {
		return map[string]blobCacheEntry{}, cacheStatusIncompatible, nil
	}
	if len(disk.Entries) > maxEntries {
		return map[string]blobCacheEntry{}, cacheStatusCorrupt, nil
	}
	valid := make(map[string]blobCacheEntry, len(disk.Entries))
	status := cacheStatusOK
	for oid, entry := range disk.Entries {
		if oid != entry.OID || !validGitOID(oid) || !validBlobCacheEntry(entry, active) {
			status = cacheStatusCorrupt
			continue
		}
		valid[oid] = entry
	}
	return valid, status, nil
}

func validBlobCacheEntry(entry blobCacheEntry, active map[string]bool) bool {
	if entry.Checksum == "" || entry.Checksum != blobCacheEntryChecksum(entry) ||
		entry.Payloads < 0 || entry.Archives < 0 || entry.EncodedPayloads < 0 ||
		entry.BytesInspected < 0 || len(entry.Warnings) > 64 || len(entry.Matches) > 100_000 {
		return false
	}
	for _, warning := range entry.Warnings {
		if len(warning) == 0 || len(warning) > 512 || strings.ContainsAny(warning, "\r\n\x00") {
			return false
		}
	}
	for _, match := range entry.Matches {
		if !active[match.DetectorID] || !validFingerprint(match.Fingerprint) ||
			match.Short != match.Fingerprint[:12] || match.Redacted == "" ||
			match.ValueLength < 1 || match.ValueLength > 1<<30 ||
			len(match.Redacted) > 4096 || match.Line < 0 ||
			len(match.Location) > 4096 || len(match.Decoder) > 256 ||
			!validConfidence(match.Confidence) {
			return false
		}
	}
	matches := make([]detector.Match, 0, len(entry.Matches))
	for _, match := range entry.Matches {
		matches = append(matches, detector.Match{
			DetectorID: match.DetectorID, Redacted: match.Redacted,
			Fingerprint: match.Fingerprint, Short: match.Short, ValueLength: match.ValueLength,
			Line: match.Line, Confidence: match.Confidence,
			Location: match.Location, Decoder: match.Decoder,
		})
	}
	scrubber, valid := detector.NewCaptureScrubber(matches)
	if !valid {
		return false
	}
	checked := map[string]bool{}
	for _, warning := range entry.Warnings {
		checked[warning] = true
	}
	for _, match := range entry.Matches {
		for _, value := range []string{match.DetectorID, match.Redacted, match.Location, match.Decoder} {
			checked[value] = true
		}
	}
	for value := range checked {
		if scrubber.Contains(value) {
			return false
		}
	}
	return true
}

func validConfidence(confidence model.Confidence) bool {
	switch confidence {
	case model.ConfidenceUncertain, model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh, model.ConfidenceConfirmed:
		return true
	default:
		return false
	}
}

func validFingerprint(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validGitOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	if strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func blobCacheEntryChecksum(entry blobCacheEntry) string {
	entry.Checksum = ""
	encoded, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func marshalBoundedBlobCache(semantics string, entries map[string]blobCacheEntry, maxEntries int, maxBytes int64) ([]byte, map[string]blobCacheEntry, error) {
	type candidate struct {
		oid      string
		lastUsed int64
	}
	order := make([]candidate, 0, len(entries))
	for oid, entry := range entries {
		order = append(order, candidate{oid: oid, lastUsed: entry.LastUsedUnix})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].lastUsed != order[j].lastUsed {
			return order[i].lastUsed < order[j].lastUsed
		}
		return order[i].oid < order[j].oid
	})
	retained := make(map[string]blobCacheEntry, min(len(entries), maxEntries))
	start := max(0, len(order)-maxEntries)
	for _, item := range order[start:] {
		retained[item.oid] = entries[item.oid]
	}
	for {
		disk := blobCacheFile{
			Format: blobCacheFormat, Version: blobCacheVersion, Semantics: semantics,
			WrittenAt: time.Now().UTC(), Entries: retained,
		}
		encoded, err := json.Marshal(disk)
		if err != nil {
			return nil, nil, err
		}
		body := append([]byte(blobCacheMagic), encoded...)
		if int64(len(body)) <= maxBytes {
			return body, retained, nil
		}
		if len(retained) == 0 {
			return nil, nil, fmt.Errorf("blob cache byte limit is too small for its header")
		}
		overage := float64(len(body)-int(maxBytes)) / float64(len(body))
		drop := max(1, int(float64(len(retained))*overage*1.2))
		for _, item := range order {
			if _, exists := retained[item.oid]; !exists {
				continue
			}
			delete(retained, item.oid)
			drop--
			if drop == 0 {
				break
			}
		}
	}
}

func acquireBlobCacheLock(path string) (func(), error) {
	if err := os.Mkdir(path, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errCacheBusy
		}
		return nil, err
	}
	return func() {
		_ = os.Remove(path)
	}, nil
}

func writeBlobCacheAtomic(root, path string, body []byte) (err error) {
	if err := validateBlobCachePath(root, path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0600); err != nil {
		return err
	}
	if _, err = temp.Write(body); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = validateBlobCachePath(root, path); err != nil {
		return err
	}
	if err = replaceCacheFile(tempPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
