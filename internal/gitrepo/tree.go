package gitrepo

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	maxTreeObjectSize = int64(64 * 1024 * 1024)
	maxTreeDepth      = 256
)

type TreeStats struct {
	TreesRead int
	CacheHits int
}

// TreeWalker reads and caches raw Git tree objects through one batch process.
// Shared subtrees are parsed once even when they appear in thousands of
// commits, avoiding one `git ls-tree` process per commit.
type TreeWalker struct {
	reader *BatchBlobReader
	cache  map[string][]treeEntry
	stats  TreeStats
}

type treeEntry struct {
	mode string
	name string
	oid  string
}

func (r *Repo) NewTreeWalker(ctx context.Context) (*TreeWalker, error) {
	reader, err := r.NewBatchBlobReader(ctx)
	if err != nil {
		return nil, err
	}
	return &TreeWalker{reader: reader, cache: map[string][]treeEntry{}}, nil
}

func (w *TreeWalker) BlobsAtCommit(commit Commit) ([]Blob, error) {
	if !validObjectID(commit.Hash) || !validObjectID(commit.Tree) {
		return nil, fmt.Errorf("commit metadata contains an invalid object ID")
	}
	var blobs []Blob
	active := map[string]bool{}
	if err := w.walk(commit.Tree, "", commit.Hash, 0, active, &blobs); err != nil {
		return nil, err
	}
	return blobs, nil
}

func (w *TreeWalker) Stats() TreeStats {
	return w.stats
}

func (w *TreeWalker) Close() error {
	return w.reader.Close()
}

func (w *TreeWalker) walk(treeOID, prefix, commit string, depth int, active map[string]bool, blobs *[]Blob) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("Git tree depth exceeds %d", maxTreeDepth)
	}
	if active[treeOID] {
		return fmt.Errorf("Git tree cycle detected")
	}
	active[treeOID] = true
	defer delete(active, treeOID)

	entries, ok := w.cache[treeOID]
	if ok {
		w.stats.CacheHits++
	} else {
		object, err := w.reader.ReadObject(treeOID, maxTreeObjectSize)
		if err != nil {
			return err
		}
		if object.Type != "tree" {
			return fmt.Errorf("Git object %s has type %s, not tree", treeOID, object.Type)
		}
		entries, err = parseTreeObject(object.Data, len(treeOID)/2)
		if err != nil {
			return fmt.Errorf("parse Git tree %s: %w", treeOID, err)
		}
		w.cache[treeOID] = entries
		w.stats.TreesRead++
	}

	for _, entry := range entries {
		entryPath := entry.name
		if prefix != "" {
			entryPath = prefix + "/" + entry.name
		}
		switch entry.mode {
		case "40000", "040000":
			if err := w.walk(entry.oid, entryPath, commit, depth+1, active, blobs); err != nil {
				return err
			}
		case "160000":
			// Gitlink/submodule commit. The containing repository has no blob
			// bytes for this entry; .gitmodules is reported separately.
			continue
		default:
			*blobs = append(*blobs, Blob{Commit: commit, OID: entry.oid, Path: entryPath, Size: -1, Mode: entry.mode})
		}
	}
	return nil
}

func parseTreeObject(data []byte, hashBytes int) ([]treeEntry, error) {
	if hashBytes != 20 && hashBytes != 32 {
		return nil, fmt.Errorf("unsupported Git object ID width")
	}
	entries := make([]treeEntry, 0)
	for offset := 0; offset < len(data); {
		space := indexByte(data, ' ', offset)
		if space < 0 || space == offset {
			return nil, fmt.Errorf("malformed mode")
		}
		nul := indexByte(data, 0, space+1)
		if nul < 0 || nul == space+1 {
			return nil, fmt.Errorf("malformed path")
		}
		oidStart := nul + 1
		oidEnd := oidStart + hashBytes
		if oidEnd > len(data) {
			return nil, fmt.Errorf("truncated object ID")
		}
		mode := string(data[offset:space])
		name := string(data[space+1 : nul])
		if !validTreeMode(mode) || name == "." || name == ".." || strings.Contains(name, "/") {
			return nil, fmt.Errorf("unsafe or invalid tree entry")
		}
		entries = append(entries, treeEntry{mode: mode, name: name, oid: hex.EncodeToString(data[oidStart:oidEnd])})
		offset = oidEnd
	}
	return entries, nil
}

func validTreeMode(mode string) bool {
	switch mode {
	case "40000", "040000", "100644", "100755", "120000", "160000":
		return true
	default:
		return false
	}
}

func indexByte(data []byte, target byte, start int) int {
	for index := start; index < len(data); index++ {
		if data[index] == target {
			return index
		}
	}
	return -1
}
