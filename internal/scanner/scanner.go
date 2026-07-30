package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	contentx "github.com/khushi/reporeaper/internal/content"
	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/gitrepo"
	"github.com/khushi/reporeaper/internal/model"
	"github.com/khushi/reporeaper/internal/risk"
	"github.com/khushi/reporeaper/internal/timeline"
)

type Options struct {
	Config    model.ScanConfig
	Detectors []detector.Detector
	Version   string
	Cache     CacheOptions
}

type scanState struct {
	detectors  []detector.Detector
	aggregated map[string]*model.Finding
	presence   map[string]map[string]bool
	scrubbers  map[string]detector.CaptureScrubber
	proofs     map[string]detector.Match
}

func Scan(ctx context.Context, repoPath string, opts Options) (model.Report, error) {
	start := time.Now()
	if opts.Config.Workers < 1 {
		opts.Config.Workers = 1
	}
	if opts.Config.MaxFileSize < 1 {
		return model.Report{}, fmt.Errorf("max file size must be positive")
	}
	opts.Config.DetectorSignatures = make(map[string]string, len(opts.Detectors))
	for _, activeDetector := range opts.Detectors {
		opts.Config.DetectorSignatures[activeDetector.ID()] = detector.ScanSignature(activeDetector.Signature(), contentx.SemanticsVersion)
	}
	repo, err := gitrepo.Open(ctx, repoPath)
	if err != nil {
		return model.Report{}, err
	}
	head, headErr := repo.Head(ctx)
	branch, branchErr := repo.Branch(ctx)
	shallow, shallowErr := repo.IsShallow(ctx)
	report := model.Report{
		DocumentType:  model.ScanReportDocumentType,
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   opts.Version,
		GeneratedAt:   time.Now().UTC(),
		Config:        opts.Config,
		Findings:      []model.Finding{},
		Repository: model.Repository{
			Path: repo.Path, GitDir: repo.GitDir(ctx), Head: head, Branch: branch,
			Bare: repo.Bare, Shallow: shallow, WorktreeOK: !repo.Bare, IndexOK: !repo.Bare,
		},
		Summary: model.Summary{FindingsBySeverity: map[model.Severity]int{}},
	}
	warnings := map[string]bool{}
	addWarning := func(message string) {
		if !warnings[message] {
			warnings[message] = true
			report.Warnings = append(report.Warnings, message)
		}
	}
	notices := map[string]bool{}
	addNotice := func(message string) {
		if !notices[message] {
			notices[message] = true
			report.Notices = append(report.Notices, message)
		}
	}
	var cache *blobCache
	if opts.Cache.Enabled {
		gitDir := repo.GitDir(ctx)
		cacheRoot := filepath.Join(gitDir, "reporeaper")
		cachePath := opts.Cache.Path
		if cachePath == "" {
			cachePath = filepath.Join(cacheRoot, "blob-scan-cache-v1")
		} else if !filepath.IsAbs(cachePath) {
			cachePath = filepath.Join(cacheRoot, cachePath)
		}
		resolvedCacheRoot, rootErr := filepath.Abs(cacheRoot)
		if rootErr != nil {
			addNotice("persistent blob scan cache directory could not be resolved; cache use was disabled")
		}
		resolvedCachePath, pathErr := filepath.Abs(cachePath)
		if pathErr != nil {
			addNotice("persistent blob scan cache path could not be resolved; cache use was disabled")
		} else if rootErr != nil {
			// The directory notice above already explains why the optional
			// cache was disabled.
		} else if !pathWithinDirectory(resolvedCacheRoot, resolvedCachePath) {
			addNotice("persistent blob scan cache must be stored inside the dedicated repository Git cache directory; cache use was disabled")
		} else {
			cacheWarnings := []string(nil)
			openedCache, cacheWarnings := openBlobCache(
				resolvedCacheRoot,
				resolvedCachePath,
				cacheSemantics(opts.Detectors, opts.Config.MaxFileSize),
				opts.Detectors,
				opts.Cache.MaxEntries,
				opts.Cache.MaxBytes,
			)
			for _, warning := range cacheWarnings {
				addNotice(warning)
			}
			if openedCache.writable {
				cache = openedCache
			}
		}
	}
	opts.Config.CacheEnabled = cache != nil && cache.writable
	report.Config.CacheEnabled = opts.Config.CacheEnabled
	if headErr != nil {
		addWarning("HEAD could not be resolved; current-commit attribution may be incomplete")
	}
	if branchErr != nil {
		addWarning("current branch metadata could not be read")
	}
	if shallowErr != nil {
		addWarning("repository shallow status could not be determined")
	}
	if report.Repository.Shallow {
		addWarning("repository is shallow; history analysis is incomplete")
	}
	remotes, remoteErr := repo.Remotes(ctx)
	if remoteErr != nil {
		addWarning("remote metadata could not be enumerated")
	}
	for _, remote := range remotes {
		report.Repository.Remotes = append(report.Repository.Remotes, model.Remote{Name: remote.Name, URL: remote.URL})
	}

	refs, err := repo.Refs(ctx, opts.Config.Branches, opts.Config.Tags, opts.Config.AllRefs)
	if err != nil {
		return model.Report{}, fmt.Errorf("enumerate refs: %w", err)
	}
	if head != "" {
		headIncluded := false
		for _, ref := range refs {
			if ref.Hash == head {
				headIncluded = true
				break
			}
		}
		if !headIncluded {
			refs = append(refs, gitrepo.Ref{Name: "HEAD", Hash: head})
		}
	}
	commits, err := repo.Commits(ctx, refs, opts.Config.Since, opts.Config.Until)
	if err != nil {
		return model.Report{}, fmt.Errorf("enumerate commits: %w", err)
	}
	commitByHash := make(map[string]gitrepo.Commit, len(commits))
	for _, commit := range commits {
		commitByHash[commit.Hash] = commit
	}
	if head != "" {
		if _, included := commitByHash[head]; !included {
			headCommit, infoErr := repo.CommitInfo(ctx, head)
			if infoErr != nil {
				return model.Report{}, fmt.Errorf("inspect HEAD snapshot: %w", infoErr)
			}
			commits = append(commits, headCommit)
			commitByHash[head] = headCommit
		}
	}
	state := scanState{
		detectors: opts.Detectors, aggregated: map[string]*model.Finding{},
		presence: map[string]map[string]bool{}, scrubbers: map[string]detector.CaptureScrubber{},
		proofs: map[string]detector.Match{},
	}

	if !repo.Bare {
		worktreeFiles, listErr := repo.WorktreeFiles(ctx, opts.Config.IncludeUntracked)
		if listErr != nil {
			addWarning("working-tree file enumeration was incomplete")
			report.Repository.WorktreeOK = false
		}
		for _, file := range worktreeFiles {
			if err := ctx.Err(); err != nil {
				return model.Report{}, err
			}
			normalizedPath := filepath.ToSlash(file.Path)
			content, readErr := repo.FileBytes(file.Path, opts.Config.MaxFileSize)
			if readErr != nil {
				switch {
				case errors.Is(readErr, gitrepo.ErrWorktreeFileTooLarge):
					addWarning("one or more working-tree files exceeded the configured size limit")
				case errors.Is(readErr, gitrepo.ErrWorktreeSymlink):
					addWarning("working-tree symbolic links were not followed")
				case errors.Is(readErr, gitrepo.ErrWorktreeNotRegular):
					addWarning("non-regular working-tree paths were not read")
				default:
					addWarning("one or more working-tree files could not be read")
				}
				report.Stats.ObjectsSkipped++
				continue
			}
			if isLFSPointer(content) {
				addWarning("Git LFS pointer files were found; referenced LFS content was not scanned")
			}
			scanned := findMatches(opts.Detectors, content, opts.Config.MaxFileSize)
			for _, warning := range scanned.warnings {
				addWarning(warning)
			}
			state.add(scanned.matches, model.Evidence{Source: "working-tree", Path: normalizedPath, Time: time.Now().UTC(), Untracked: file.Untracked})
			addContentStats(&report.Stats, scanned)
			report.Stats.ObjectsScanned++
		}
	}

	blobEvidence := map[string][]model.Evidence{}
	if !repo.Bare {
		indexBlobs, indexErr := repo.IndexBlobs(ctx)
		if indexErr != nil {
			addWarning("Git index enumeration was incomplete")
			report.Repository.IndexOK = false
		}
		for _, blob := range indexBlobs {
			if blob.Mode == "160000" {
				addWarning("submodule index entries were found; submodule repositories were not recursively scanned")
				continue
			}
			ref := ""
			if blob.Stage != 0 {
				ref = fmt.Sprintf("stage-%d", blob.Stage)
				addNotice("unresolved Git index stages were inspected")
			}
			blobEvidence[blob.OID] = append(blobEvidence[blob.OID], model.Evidence{
				Source: "index",
				Blob:   blob.OID,
				Path:   filepath.ToSlash(blob.Path),
				Ref:    ref,
			})
		}
	}
	treeWalker, treeWalkerErr := repo.NewTreeWalker(ctx)
	if treeWalkerErr != nil {
		addWarning("Git batch tree reader was unavailable; falling back to individual tree commands")
	}
	queueCommit := func(commit gitrepo.Commit, source, ref string, unreachable, reflog bool) {
		var blobs []gitrepo.Blob
		var listErr error
		if treeWalker != nil {
			blobs, listErr = treeWalker.BlobsAtCommit(commit)
			if listErr != nil {
				// Keep a malformed or unsupported batch-tree response from
				// creating a history blind spot. The compatibility path is
				// slower, but still uses argv-based Git execution in gitrepo.
				blobs, listErr = repo.BlobsAtCommit(ctx, commit.Hash)
			}
		} else {
			blobs, listErr = repo.BlobsAtCommit(ctx, commit.Hash)
		}
		if listErr != nil {
			addWarning("one or more Git trees or objects could not be inspected")
			return
		}
		for _, blob := range blobs {
			if blob.Path == ".gitmodules" {
				addWarning("submodule references were found; submodule repositories were not recursively scanned")
			}
			blobEvidence[blob.OID] = append(blobEvidence[blob.OID], model.Evidence{
				Source: source, Commit: commit.Hash, Blob: blob.OID, Path: filepath.ToSlash(blob.Path), Ref: ref,
				AuthorName: commit.AuthorName, AuthorEmail: commit.AuthorEmail, Time: commit.Time,
				Unreachable: unreachable, Reflog: reflog, InHead: commit.Hash == head,
			})
		}
	}
	queueDirectRef := func(ref gitrepo.Ref) {
		target := ref.Target
		if target == "" {
			target = ref.Hash
		}
		var blobs []gitrepo.Blob
		var listErr error
		switch ref.Type {
		case "blob":
			blobs = []gitrepo.Blob{{OID: target, Path: "", Size: -1}}
		case "tree":
			blobs, listErr = repo.BlobsAtTree(ctx, target)
		default:
			return
		}
		if listErr != nil {
			addWarning("one or more direct Git ref objects could not be inspected")
			return
		}
		for _, blob := range blobs {
			blobEvidence[blob.OID] = append(blobEvidence[blob.OID], model.Evidence{
				Source: "ref-object", Blob: blob.OID, Path: filepath.ToSlash(blob.Path), Ref: ref.Name,
			})
		}
	}
	for _, ref := range refs {
		queueDirectRef(ref)
	}
	for _, commit := range commits {
		queueCommit(commit, "commit-history", "", false, false)
		report.Stats.CommitsAnalyzed++
	}

	if opts.Config.Reflogs {
		reflogRefs, reflogErr := repo.ReflogCommits(ctx)
		if reflogErr != nil {
			addWarning("reflog enumeration was incomplete")
		}
		for _, reflogRef := range reflogRefs {
			if _, reachable := commitByHash[reflogRef.Hash]; reachable {
				continue
			}
			commit, infoErr := repo.CommitInfo(ctx, reflogRef.Hash)
			if infoErr != nil {
				addWarning("one or more reflog commits were unavailable")
				continue
			}
			queueCommit(commit, "reflog", reflogRef.Name, false, true)
			report.Stats.CommitsAnalyzed++
		}
	}

	if opts.Config.Unreachable {
		objects, objectErr := repo.UnreachableObjects(ctx)
		if objectErr != nil {
			addWarning("unreachable-object enumeration was incomplete")
		}
		for _, object := range objects {
			switch object.Type {
			case "commit":
				commit, infoErr := repo.CommitInfo(ctx, object.OID)
				if infoErr != nil {
					addWarning("one or more unreachable commits were unavailable")
					continue
				}
				queueCommit(commit, "unreachable-commit", "", true, false)
				report.Stats.CommitsAnalyzed++
			case "blob":
				blobEvidence[object.OID] = append(blobEvidence[object.OID], model.Evidence{Source: "unreachable-blob", Blob: object.OID, Unreachable: true})
			}
		}
	}
	if treeWalker != nil {
		treeStats := treeWalker.Stats()
		report.Stats.TreesRead = treeStats.TreesRead
		report.Stats.TreeCacheHits = treeStats.CacheHits
		if closeErr := treeWalker.Close(); closeErr != nil && ctx.Err() == nil {
			addWarning("Git batch tree reader did not close cleanly")
		}
	}

	if err := scanBlobs(ctx, repo, opts.Detectors, opts.Config.Workers, opts.Config.MaxFileSize, blobEvidence, &state, &report, cache, addWarning, addNotice); err != nil {
		return model.Report{}, err
	}
	if cache != nil {
		if err := cache.save(); err != nil {
			if errors.Is(err, errCacheBusy) {
				addNotice("persistent blob scan cache was busy; scan results were not written to the cache")
			} else {
				addNotice("persistent blob scan cache could not be written; scan results remain valid but were not persisted")
			}
		}
	}

	for _, key := range sortedKeys(state.aggregated) {
		finding := *state.aggregated[key]
		finalize(ctx, repo, head, commits, state.presence[key], state.scrubbers[key], &finding, addWarning)
		report.Findings = append(report.Findings, finding)
	}
	for i := range report.Findings {
		report.Findings[i].ID = fmt.Sprintf("RR-%04d", i+1)
	}
	proofs := make([]detector.Match, 0, len(state.proofs))
	for _, fingerprint := range sortedKeys(state.proofs) {
		proofs = append(proofs, state.proofs[fingerprint])
	}
	reportScrubber, _ := detector.NewCaptureScrubber(proofs)
	scrubScanReport(&report, reportScrubber)
	recalculateSummary(&report)
	sort.Strings(report.Warnings)
	sort.Strings(report.Notices)
	report.Stats.DurationMillis = time.Since(start).Milliseconds()
	return report, nil
}

type blobResult struct {
	oid     string
	scanned contentScanResult
	lfs     bool
	err     error
}

func scanBlobs(ctx context.Context, repo *gitrepo.Repo, detectors []detector.Detector, workers int, maxFileSize int64, evidence map[string][]model.Evidence, state *scanState, report *model.Report, cache *blobCache, warn, notice func(string)) error {
	oids := sortedKeys(evidence)
	if len(oids) == 0 {
		return ctx.Err()
	}
	pending := make([]string, 0, len(oids))
	for _, oid := range oids {
		if cache != nil {
			if scanned, lfs, ok := cache.get(oid); ok {
				report.Stats.BlobCacheHits++
				processBlobResult(blobResult{oid: oid, scanned: scanned, lfs: lfs}, evidence, state, report, warn)
				continue
			}
			report.Stats.BlobCacheMisses++
		}
		pending = append(pending, oid)
	}
	if len(pending) == 0 {
		return ctx.Err()
	}
	workers = min(workers, len(pending))
	readers := make([]*gitrepo.BatchBlobReader, 0, workers)
	for range workers {
		reader, err := repo.NewBatchBlobReader(ctx)
		if err != nil {
			for _, opened := range readers {
				_ = opened.Close()
			}
			return err
		}
		readers = append(readers, reader)
	}
	jobs := make(chan string)
	results := make(chan blobResult, workers)
	var wg sync.WaitGroup
	for _, reader := range readers {
		wg.Add(1)
		go func(reader *gitrepo.BatchBlobReader) {
			defer wg.Done()
			defer reader.Close()
			for oid := range jobs {
				content, err := reader.ReadBlob(oid, maxFileSize)
				result := blobResult{oid: oid, err: err}
				if err == nil {
					result.lfs = isLFSPointer(content)
					result.scanned = findMatches(detectors, content, maxFileSize)
				}
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}(reader)
	}
	go func() {
		defer close(jobs)
		for _, oid := range pending {
			select {
			case jobs <- oid:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	for result := range results {
		if result.err == nil && cache != nil && !cache.put(result.oid, result.scanned, result.lfs) {
			notice("one or more Git blob scan results could not be safely represented in the persistent cache")
		}
		processBlobResult(result, evidence, state, report, warn)
	}
	return ctx.Err()
}

func processBlobResult(result blobResult, evidence map[string][]model.Evidence, state *scanState, report *model.Report, warn func(string)) {
	if result.err != nil {
		if errors.Is(result.err, gitrepo.ErrObjectTooLarge) {
			report.Stats.ObjectsSkipped++
			warn("one or more Git objects exceeded the configured size limit")
			return
		}
		report.Stats.ObjectsSkipped++
		warn("one or more Git blobs could not be read")
		return
	}
	if result.lfs {
		warn("Git LFS pointer files were found; referenced LFS content was not scanned")
	}
	for _, warning := range result.scanned.warnings {
		warn(warning)
	}
	addContentStats(&report.Stats, result.scanned)
	report.Stats.ObjectsScanned++
	if len(evidence[result.oid]) > 1 {
		report.Stats.BlobsDeduplicated += len(evidence[result.oid]) - 1
	}
	scrubber, _ := detector.NewCaptureScrubber(result.scanned.matches)
	for _, ev := range evidence[result.oid] {
		state.addWithScrubber(result.scanned.matches, ev, scrubber)
	}
}

type contentScanResult struct {
	matches         []detector.Match
	warnings        []string
	payloads        int
	archives        int
	encodedPayloads int
	bytesInspected  int64
}

func findMatches(detectors []detector.Detector, content []byte, maxFileSize int64) contentScanResult {
	expanded := contentx.Expand(content, contentx.Limits{MaxUnitSize: maxFileSize})
	result := contentScanResult{
		warnings: expanded.Warnings, payloads: len(expanded.Units),
		archives: expanded.ArchivesOpened, encodedPayloads: expanded.EncodedPayloads,
		bytesInspected: expanded.BytesInspected,
	}
	for _, unit := range expanded.Units {
		prepared := detector.PrepareText(unit.Data)
		for _, d := range detectors {
			for _, match := range detector.FindPrepared(d, prepared) {
				if match.Location == "" {
					match.Location = unit.Location
				} else if unit.Location != "" {
					match.Location = unit.Location + "!" + match.Location
				}
				if unit.Decoder == "" {
					// Preserve detector-provided provenance for structured formats.
				} else if match.Decoder == "" {
					match.Decoder = unit.Decoder
				} else {
					match.Decoder = unit.Decoder + "+" + match.Decoder
				}
				if unit.SourceLine > 0 {
					match.Line = unit.SourceLine
				}
				result.matches = append(result.matches, match)
			}
		}
	}
	sanitized, scrubber, _ := detector.SanitizeMatches(result.matches)
	result.matches = sanitized
	for index := range result.warnings {
		result.warnings[index] = scrubber.Scrub(result.warnings[index])
	}
	return result
}

func addContentStats(stats *model.ScanStats, result contentScanResult) {
	stats.PayloadsScanned += result.payloads
	stats.ArchivesOpened += result.archives
	stats.EncodedPayloads += result.encodedPayloads
	stats.BytesInspected += result.bytesInspected
}

func (s *scanState) add(matches []detector.Match, ev model.Evidence) {
	scrubber, _ := detector.NewCaptureScrubber(matches)
	s.addWithScrubber(matches, ev, scrubber)
}

func (s *scanState) addWithScrubber(matches []detector.Match, ev model.Evidence, scrubber detector.CaptureScrubber) {
	ev.Path = scrubber.Scrub(ev.Path)
	ev.Ref = scrubber.Scrub(ev.Ref)
	ev.AuthorName = scrubber.Scrub(ev.AuthorName)
	ev.AuthorEmail = scrubber.Scrub(ev.AuthorEmail)
	baseEvidence := ev
	for _, match := range matches {
		ev = baseEvidence
		var found detector.Detector
		for _, d := range s.detectors {
			if d.ID() == match.DetectorID {
				found = d
				break
			}
		}
		if found == nil {
			continue
		}
		key := match.Fingerprint
		findingScrubber, _ := detector.NewCaptureScrubber([]detector.Match{match})
		s.scrubbers[key] = findingScrubber
		proof := detector.Match{
			Value: match.Value, Fingerprint: match.Fingerprint,
			Short: match.Short, ValueLength: match.ValueLength,
		}
		if existing, ok := s.proofs[key]; ok && existing.Value != "" && proof.Value == "" {
			proof.Value = existing.Value
		}
		s.proofs[key] = proof
		finding := s.aggregated[key]
		if finding == nil {
			finding = &model.Finding{
				DetectorID: found.ID(), DetectorName: found.Name(), Category: found.Category(), Severity: found.Severity(),
				Confidence: match.Confidence, ConfidenceReason: "the detector pattern and configured prefilters passed; entropy and structural validation were applied where this rule defines them; no live provider validation was attempted",
				Fingerprint: match.Fingerprint, ShortFingerprint: match.Short, Redacted: match.Redacted, Remediation: found.Remediation(),
			}
			s.aggregated[key] = finding
			s.presence[key] = map[string]bool{}
		} else if severityRank(found.Severity()) > severityRank(finding.Severity) {
			finding.DetectorID = found.ID()
			finding.DetectorName = found.Name()
			finding.Category = found.Category()
			finding.Severity = found.Severity()
			finding.Redacted = match.Redacted
			finding.Remediation = found.Remediation()
		}
		if match.Location != "" {
			if ev.Path == "" {
				ev.Path = match.Location
			} else {
				ev.Path += "!" + match.Location
			}
		}
		ev.Decoder = match.Decoder
		ev.Line = match.Line
		if !hasEvidence(finding.Evidence, ev) {
			finding.Evidence = append(finding.Evidence, ev)
		}
		if ev.Commit != "" && ev.Source == "commit-history" {
			s.presence[key][ev.Commit] = true
		}
		if ev.Path != "" && !contains(finding.Paths, ev.Path) {
			finding.Paths = append(finding.Paths, ev.Path)
		}
	}
}

func hasEvidence(existing []model.Evidence, candidate model.Evidence) bool {
	for _, evidence := range existing {
		if evidence.Source == candidate.Source && evidence.Commit == candidate.Commit && evidence.Blob == candidate.Blob && evidence.Path == candidate.Path && evidence.Line == candidate.Line && evidence.Ref == candidate.Ref && evidence.Decoder == candidate.Decoder {
			return true
		}
	}
	return false
}

func severityRank(severity model.Severity) int {
	return map[model.Severity]int{
		model.SeverityInfo: 1, model.SeverityLow: 2, model.SeverityMedium: 3,
		model.SeverityHigh: 4, model.SeverityCritical: 5,
	}[severity]
}

func finalize(ctx context.Context, repo *gitrepo.Repo, head string, commits []gitrepo.Commit, present map[string]bool, scrubber detector.CaptureScrubber, finding *model.Finding, warn func(string)) {
	order := map[string]int{}
	for i, commit := range commits {
		order[commit.Hash] = i
	}
	sort.SliceStable(finding.Evidence, func(i, j int) bool {
		a, b := finding.Evidence[i], finding.Evidence[j]
		oi, iok := order[a.Commit]
		oj, jok := order[b.Commit]
		if iok && jok && oi != oj {
			return oi < oj
		}
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Source < b.Source
	})

	for _, ev := range finding.Evidence {
		finding.InWorkingTree = finding.InWorkingTree || ev.Source == "working-tree"
		finding.InTrackedWorkingTree = finding.InTrackedWorkingTree || (ev.Source == "working-tree" && !ev.Untracked)
		finding.InUntracked = finding.InUntracked || (ev.Source == "working-tree" && ev.Untracked)
		finding.InHead = finding.InHead || (ev.Source == "commit-history" && ev.Commit == head)
		finding.InIndex = finding.InIndex || ev.Source == "index"
		finding.InDirectRef = finding.InDirectRef || ev.Source == "ref-object"
		if ev.Source == "ref-object" {
			switch {
			case strings.HasPrefix(ev.Ref, "refs/tags/"):
				name := strings.TrimPrefix(ev.Ref, "refs/tags/")
				if name != "" && !contains(finding.Tags, name) {
					finding.Tags = append(finding.Tags, name)
				}
			case strings.HasPrefix(ev.Ref, "refs/heads/"), strings.HasPrefix(ev.Ref, "refs/remotes/"):
				if !contains(finding.Branches, ev.Ref) {
					finding.Branches = append(finding.Branches, ev.Ref)
				}
			}
		}
		finding.InReflog = finding.InReflog || ev.Reflog
		finding.InUnreachable = finding.InUnreachable || ev.Unreachable
	}
	finding.CommitCount = len(present)
	switch {
	case finding.InHead:
		finding.CurrentStatus = "present-in-head"
	case finding.InIndex:
		finding.CurrentStatus = "present-in-index"
	case finding.InDirectRef:
		finding.CurrentStatus = "present-in-ref-object"
	case finding.InTrackedWorkingTree:
		finding.CurrentStatus = "present-in-tracked-working-tree"
	case finding.InUntracked:
		finding.CurrentStatus = "present-in-untracked-file"
	case finding.InWorkingTree:
		finding.CurrentStatus = "present-in-working-tree"
	case finding.InReflog && finding.InUnreachable && finding.CommitCount == 0:
		finding.CurrentStatus = "reflog-and-unreachable-only"
	case finding.InReflog && finding.CommitCount == 0 && !finding.InUnreachable:
		finding.CurrentStatus = "reflog-only"
	case finding.InUnreachable && finding.CommitCount == 0 && !finding.InReflog:
		finding.CurrentStatus = "unreachable-only"
	default:
		finding.CurrentStatus = "history-only"
	}

	graph := make([]timeline.Commit, 0, len(commits))
	for _, commit := range commits {
		graph = append(graph, timeline.Commit{Hash: commit.Hash, Parents: commit.Parents, Time: commit.Time})
	}
	timelineResult := timeline.Build(graph, present, finding.CurrentStatus)
	finding.ExposureIntervals = timelineResult.Intervals
	refCommits := map[string]bool{}
	for _, commit := range timelineResult.Introductions {
		refCommits[commit] = true
	}
	for _, evidence := range finding.Evidence {
		if evidence.Commit != "" && (evidence.Source != "commit-history" || !present[evidence.Commit]) {
			refCommits[evidence.Commit] = true
		}
	}
	if len(refCommits) == 0 {
		for _, evidence := range finding.Evidence {
			if evidence.Commit != "" {
				refCommits[evidence.Commit] = true
				break
			}
		}
	}
	for _, commit := range sortedKeys(refCommits) {
		branches, tags, err := repo.ContainingRefs(ctx, commit)
		if err != nil {
			warn("one or more branch or tag containment checks failed")
			continue
		}
		for _, branch := range branches {
			branch = scrubber.Scrub(branch)
			if branch != "" && !contains(finding.Branches, branch) {
				finding.Branches = append(finding.Branches, branch)
			}
		}
		for _, tag := range tags {
			tag = scrubber.Scrub(tag)
			if tag != "" && !contains(finding.Tags, tag) {
				finding.Tags = append(finding.Tags, tag)
			}
		}
	}
	if len(timelineResult.Introductions) > 0 {
		finding.Introduced = evidenceForCommit(finding.Evidence, timelineResult.Introductions[0])
	}
	if len(timelineResult.Removals) > 0 {
		if commit, ok := commitByHash(commits, timelineResult.Removals[0]); ok {
			finding.Removed = &model.Evidence{Source: "commit-history", Commit: commit.Hash, AuthorName: commit.AuthorName, AuthorEmail: commit.AuthorEmail, Time: commit.Time}
		}
	}
	if len(finding.Evidence) > 0 {
		finding.FirstSeen = firstDatedEvidence(finding.Evidence)
		finding.LastSeen = lastDatedEvidence(finding.Evidence)
	}
	finding.ExposureDurationSeconds = exposureDuration(finding.ExposureIntervals, commits, finding.LastSeen)
	if timelineResult.Ambiguous {
		finding.Confidence = model.ConfidenceMedium
		finding.ConfidenceReason = "the value matched detector validation, but merge topology makes the exact introduction or removal path ambiguous"
	}
	sort.Strings(finding.Paths)
	sort.Strings(finding.Branches)
	sort.Strings(finding.Tags)
	finding.RemoteStatus, finding.RemoteReason = remoteStatus(finding)
	finding.RiskScore, finding.RiskExplanation = risk.Score(*finding)
}

type timeRange struct {
	start time.Time
	end   time.Time
}

func exposureDuration(intervals []model.ExposureInterval, commits []gitrepo.Commit, lastSeen *model.Evidence) int64 {
	commitTimes := make(map[string]time.Time, len(commits))
	for _, commit := range commits {
		commitTimes[commit.Hash] = commit.Time
	}
	ranges := make([]timeRange, 0, len(intervals))
	for _, interval := range intervals {
		end := interval.EndedAt
		if end.IsZero() {
			end = commitTimes[interval.EndCommit]
		}
		if end.IsZero() && lastSeen != nil {
			end = lastSeen.Time
		}
		if end.After(interval.StartedAt) {
			ranges = append(ranges, timeRange{start: interval.StartedAt, end: end})
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start.Equal(ranges[j].start) {
			return ranges[i].end.Before(ranges[j].end)
		}
		return ranges[i].start.Before(ranges[j].start)
	})
	var total int64
	for index := 0; index < len(ranges); {
		start, end := ranges[index].start, ranges[index].end
		index++
		for index < len(ranges) && !ranges[index].start.After(end) {
			if ranges[index].end.After(end) {
				end = ranges[index].end
			}
			index++
		}
		total += int64(end.Sub(start).Seconds())
	}
	return total
}

func recalculateSummary(report *model.Report) {
	report.Summary = model.Summary{
		FindingsBySeverity:  report.Summary.FindingsBySeverity,
		SuppressedFindings:  report.Summary.SuppressedFindings,
		AllowlistSuppressed: report.Summary.AllowlistSuppressed,
		BaselineSuppressed:  report.Summary.BaselineSuppressed,
	}
	report.Summary.FindingsBySeverity = map[model.Severity]int{}
	for _, finding := range report.Findings {
		report.Summary.FindingsBySeverity[finding.Severity]++
		if finding.InWorkingTree || finding.InHead || finding.InIndex {
			report.Summary.CurrentSecrets++
		} else {
			report.Summary.HistoricalSecrets++
		}
		if finding.InUnreachable {
			report.Summary.UnreachableSecrets++
		}
	}
}

func Recalculate(report *model.Report, allowlistSuppressed, baselineSuppressed int) {
	if report.Findings == nil {
		report.Findings = []model.Finding{}
	}
	report.Summary.AllowlistSuppressed += allowlistSuppressed
	report.Summary.BaselineSuppressed += baselineSuppressed
	report.Summary.SuppressedFindings += allowlistSuppressed + baselineSuppressed
	recalculateSummary(report)
}

func remoteStatus(finding *model.Finding) (string, string) {
	for _, branch := range finding.Branches {
		if strings.HasPrefix(branch, "refs/remotes/") || strings.HasPrefix(branch, "remotes/") {
			return "confirmed-from-local-refs", "the evidence commit is contained in a local remote-tracking ref; no network request was made"
		}
	}
	if len(finding.Tags) > 0 {
		return "likely", "a local tag contains the evidence, but a remote equivalent was not verified"
	}
	if len(finding.Branches) > 0 {
		return "possible", "a local branch contains the evidence; remote presence was not checked"
	}
	if finding.InUnreachable || finding.InReflog {
		return "unknown", "residual local evidence exists without a current local ref that can support remote inference"
	}
	return "no-local-evidence", "no local remote-tracking ref contains this evidence"
}

func evidenceForCommit(evidence []model.Evidence, hash string) *model.Evidence {
	for i := range evidence {
		if evidence[i].Commit == hash {
			copy := evidence[i]
			return &copy
		}
	}
	return nil
}

func firstDatedEvidence(evidence []model.Evidence) *model.Evidence {
	if committed := datedEvidence(evidence, true, false); committed != nil {
		return committed
	}
	return datedEvidence(evidence, false, false)
}

func lastDatedEvidence(evidence []model.Evidence) *model.Evidence {
	if committed := datedEvidence(evidence, true, true); committed != nil {
		return committed
	}
	return datedEvidence(evidence, false, true)
}

func datedEvidence(evidence []model.Evidence, requireCommit, latest bool) *model.Evidence {
	var best *model.Evidence
	for i := range evidence {
		if evidence[i].Time.IsZero() || (requireCommit && evidence[i].Commit == "") {
			continue
		}
		if best == nil || (!latest && evidence[i].Time.Before(best.Time)) || (latest && evidence[i].Time.After(best.Time)) {
			copy := evidence[i]
			best = &copy
		}
	}
	return best
}

func commitByHash(commits []gitrepo.Commit, hash string) (gitrepo.Commit, bool) {
	for _, commit := range commits {
		if commit.Hash == hash {
			return commit, true
		}
	}
	return gitrepo.Commit{}, false
}

func isLFSPointer(content []byte) bool {
	return bytes.HasPrefix(content, []byte("version https://git-lfs.github.com/spec/v1\n"))
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func pathWithinDirectory(directory, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(directory), filepath.Clean(candidate))
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
