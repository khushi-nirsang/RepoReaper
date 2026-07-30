package gitrepo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrObjectMissing  = errors.New("Git object is missing")
	ErrObjectTooLarge = errors.New("Git object exceeds the configured size limit")
)

// BatchBlobReader owns one long-lived `git cat-file --batch` process. A reader
// is safe for concurrent callers, although scanners normally dedicate one
// reader to each worker so multiple Git object streams can progress in
// parallel without launching a process per object.
type BatchBlobReader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer

	mu        sync.Mutex
	closed    bool
	waited    bool
	waitErr   error
	cancelled context.Context
}

type Object struct {
	OID  string
	Type string
	Size int64
	Data []byte
}

func (r *Repo) NewBatchBlobReader(ctx context.Context) (*BatchBlobReader, error) {
	cmd := exec.CommandContext(ctx, "git", "cat-file", "--batch")
	cmd.Dir = r.Path
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open Git batch input: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open Git batch output: %w", err)
	}
	reader := &BatchBlobReader{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 64*1024), cancelled: ctx}
	cmd.Stderr = &reader.stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start Git batch reader: %w", err)
	}
	return reader, nil
}

func (r *BatchBlobReader) ReadBlob(oid string, maxSize int64) ([]byte, error) {
	object, err := r.ReadObject(oid, maxSize)
	if err != nil {
		return nil, err
	}
	if object.Type != "blob" {
		return nil, fmt.Errorf("Git object %s has type %s, not blob", oid, object.Type)
	}
	return object.Data, nil
}

func (r *BatchBlobReader) ReadObject(oid string, maxSize int64) (Object, error) {
	if !validObjectID(oid) {
		return Object{}, fmt.Errorf("invalid Git object ID")
	}
	if maxSize < 1 {
		return Object{}, fmt.Errorf("maximum object size must be positive")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Object{}, fmt.Errorf("Git batch reader is closed")
	}
	if err := r.cancelled.Err(); err != nil {
		return Object{}, err
	}
	if _, err := io.WriteString(r.stdin, oid+"\n"); err != nil {
		return Object{}, r.protocolError("write request", err)
	}
	header, err := r.stdout.ReadString('\n')
	if err != nil {
		return Object{}, r.protocolError("read response header", err)
	}
	fields := strings.Fields(strings.TrimSpace(header))
	if len(fields) == 2 && fields[1] == "missing" {
		return Object{}, fmt.Errorf("%w: %s", ErrObjectMissing, oid)
	}
	if len(fields) != 3 {
		return Object{}, r.protocolError("parse response header", fmt.Errorf("unexpected field count"))
	}
	if !strings.EqualFold(fields[0], oid) {
		return Object{}, r.protocolError("parse response header", fmt.Errorf("object ID mismatch"))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return Object{}, r.protocolError("parse object size", err)
	}
	if size > maxSize || size > int64(maxInt()) {
		if err := discardBatchBody(r.stdout, size); err != nil {
			return Object{}, r.protocolError("discard oversized object", err)
		}
		return Object{}, fmt.Errorf("%w: %s (%d bytes)", ErrObjectTooLarge, oid, size)
	}
	content := make([]byte, int(size))
	if _, err := io.ReadFull(r.stdout, content); err != nil {
		return Object{}, r.protocolError("read object body", err)
	}
	delimiter, err := r.stdout.ReadByte()
	if err != nil {
		return Object{}, r.protocolError("read object delimiter", err)
	}
	if delimiter != '\n' {
		return Object{}, r.protocolError("read object delimiter", fmt.Errorf("unexpected delimiter"))
	}
	return Object{OID: fields[0], Type: fields[1], Size: size, Data: content}, nil
}

func (r *BatchBlobReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.waitErr
	}
	r.closed = true
	_ = r.stdin.Close()
	if !r.waited {
		r.waitErr = r.cmd.Wait()
		r.waited = true
	}
	if r.waitErr != nil && r.cancelled.Err() == nil {
		return fmt.Errorf("close Git batch reader: %w: %s", r.waitErr, strings.TrimSpace(r.stderr.String()))
	}
	return r.cancelled.Err()
}

func (r *BatchBlobReader) protocolError(operation string, cause error) error {
	if err := r.cancelled.Err(); err != nil {
		return err
	}
	detail := strings.TrimSpace(r.stderr.String())
	if detail == "" {
		return fmt.Errorf("Git batch %s: %w", operation, cause)
	}
	return fmt.Errorf("Git batch %s: %w: %s", operation, cause, detail)
}

func discardBatchBody(reader *bufio.Reader, size int64) error {
	if size < 0 {
		return fmt.Errorf("invalid object size")
	}
	if _, err := io.CopyN(io.Discard, reader, size); err != nil {
		return err
	}
	delimiter, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if delimiter != '\n' {
		return fmt.Errorf("unexpected object delimiter")
	}
	return nil
}

func validObjectID(oid string) bool {
	if len(oid) != 40 && len(oid) != 64 {
		return false
	}
	for _, r := range oid {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
