package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/detector"
	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
)

var fakeCacheToken = "ghp_" + strings.Repeat("C4ch3F1xtur3AbCdEfGhIjKlMnOpQrSt", 1)

func TestBlobCacheRoundTripContainsNoRawMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024*1024)
	cache, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 100, 1024*1024)
	if len(warnings) != 0 {
		t.Fatalf("new cache warnings = %v", warnings)
	}
	result := findMatches(detectors, []byte("GITHUB_TOKEN="+fakeCacheToken+"\n"), 1024*1024)
	if len(result.matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(result.matches))
	}
	oid := strings.Repeat("a", 40)
	if !cache.put(oid, result, false) {
		t.Fatal("safe result was not cacheable")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(fakeCacheToken)) {
		t.Fatal("raw fake token was persisted in the cache")
	}
	if !bytes.HasPrefix(data, []byte(blobCacheMagic)) {
		t.Fatal("versioned cache header missing")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("cache permissions = %o, want 600", got)
		}
	}

	reopened, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 100, 1024*1024)
	if len(warnings) != 0 {
		t.Fatalf("reopen warnings = %v", warnings)
	}
	got, lfs, ok := reopened.get(oid)
	if !ok || lfs || len(got.matches) != 1 {
		t.Fatalf("cached result = ok %v lfs %v %#v", ok, lfs, got)
	}
	if got.matches[0].Value != "" || got.matches[0].Fingerprint != result.matches[0].Fingerprint ||
		got.matches[0].Redacted != result.matches[0].Redacted {
		t.Fatalf("cached match metadata = %#v", got.matches[0])
	}
}

func TestBlobCacheScrubsEveryCapturedValueFromMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "blob-cache")
	detectors := cacheTestDetectors(t)
	cache, warnings := openBlobCache(root, path, cacheSemantics(detectors, 1024), detectors, 10, 1024*1024)
	if len(warnings) != 0 {
		t.Fatalf("new cache warnings = %v", warnings)
	}
	firstValue := fakeCacheToken
	secondValue := "ghp_" + strings.Repeat("An0therSynth3ticCacheValue987654321", 1)
	firstFull, firstShort := fingerprint.SHA256(firstValue)
	secondFull, secondShort := fingerprint.SHA256(secondValue)
	result := contentScanResult{
		warnings: []string{"synthetic warning " + firstValue},
		matches: []detector.Match{
			{
				DetectorID: "github-token", Value: firstValue,
				Fingerprint: firstFull, Short: firstShort, Confidence: model.ConfidenceHigh,
				Redacted: "related=" + secondValue, Location: "archive/" + firstValue, Decoder: "zip",
			},
			{
				DetectorID: "github-token", Value: secondValue,
				Fingerprint: secondFull, Short: secondShort, Confidence: model.ConfidenceHigh,
				Redacted: "ghp_******4321", Location: "ordinary.env", Decoder: "zip",
			},
		},
	}
	oid := strings.Repeat("9", 40)
	if !cache.put(oid, result, false) {
		t.Fatal("sanitizable result was not cacheable")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, captured := range []string{firstValue, secondValue} {
		if bytes.Contains(data, []byte(captured)) {
			t.Fatalf("captured value %q was persisted in cache metadata", captured)
		}
	}

	reopened, warnings := openBlobCache(root, path, cacheSemantics(detectors, 1024), detectors, 10, 1024*1024)
	if len(warnings) != 0 {
		t.Fatalf("reopen warnings = %v", warnings)
	}
	cached, _, ok := reopened.get(oid)
	if !ok || len(cached.matches) != 2 {
		t.Fatalf("cached matches = ok %v %#v", ok, cached.matches)
	}
	scrubber, valid := detector.NewCaptureScrubber(cached.matches)
	if !valid {
		t.Fatal("cached fingerprint-and-length metadata was invalid")
	}
	evidence := "refs/heads/" + firstValue
	if scrubbed := scrubber.Scrub(evidence); strings.Contains(scrubbed, firstValue) || scrubbed == evidence {
		t.Fatalf("cache-hit evidence was not scrubbed: %q", scrubbed)
	}
}

func TestBlobCacheSemanticsInvalidateEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	cache, _ := openBlobCache(filepath.Dir(path), path, cacheSemantics(detectors, 1024), detectors, 10, 1024*1024)
	oid := strings.Repeat("b", 40)
	if !cache.put(oid, contentScanResult{payloads: 1}, false) {
		t.Fatal("empty result was not cacheable")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}
	changedSize, warnings := openBlobCache(filepath.Dir(path), path, cacheSemantics(detectors, 2048), detectors, 10, 1024*1024)
	if len(warnings) != 0 {
		t.Fatalf("semantic miss should not warn: %v", warnings)
	}
	if _, _, ok := changedSize.get(oid); ok {
		t.Fatal("entry survived a max-file-size semantics change")
	}

	changedRule, err := detector.NewRegex(
		"cache-test", "Cache test", "Fake cache test detector", "test",
		model.SeverityHigh, []string{"token"}, `token=([A-Za-z0-9]{24,})`, 0, nil,
		[]string{"Rotate the fake fixture."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cacheSemantics(detectors, 1024) == cacheSemantics([]detector.Detector{changedRule}, 1024) {
		t.Fatal("detector definition change did not alter cache semantics")
	}
}

func TestBlobCacheSemanticsPreserveDetectorOrder(t *testing.T) {
	first, err := detector.NewRegex(
		"first-order", "First", "Synthetic first ordering detector", "test",
		model.SeverityMedium, []string{"credential"}, `credential=([A-Za-z0-9]{24,})`,
		0, nil, []string{"Replace the synthetic fixture."},
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := detector.NewRegex(
		"second-order", "Second", "Synthetic second ordering detector", "test",
		model.SeverityMedium, []string{"credential"}, `credential=([A-Za-z0-9]{24,})`,
		0, nil, []string{"Replace the synthetic fixture."},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cacheSemantics([]detector.Detector{first, second}, 1024) ==
		cacheSemantics([]detector.Detector{second, first}, 1024) {
		t.Fatal("detector order did not alter cache semantics")
	}
}

func TestBlobCacheCorruptionWarnsAndMisses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024)
	cache, _ := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
	oid := strings.Repeat("c", 40)
	result := findMatches(detectors, []byte("token="+fakeCacheToken), 1024)
	if !cache.put(oid, result, false) {
		t.Fatal("result was not cacheable")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk blobCacheFile
	if err := json.Unmarshal(data[len(blobCacheMagic):], &disk); err != nil {
		t.Fatal(err)
	}
	entry := disk.Entries[oid]
	entry.Matches[0].Redacted = "tampered"
	disk.Entries[oid] = entry
	body, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(blobCacheMagic), body...), 0600); err != nil {
		t.Fatal(err)
	}

	reopened, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
	if len(warnings) == 0 || !strings.Contains(warnings[0], "invalid entries") {
		t.Fatalf("corruption warning = %v", warnings)
	}
	if _, _, ok := reopened.get(oid); ok {
		t.Fatal("corrupted entry was treated as a hit")
	}
}

func TestBlobCacheRejectsCapturedValueWithRecomputedChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024)
	cache, _ := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
	oid := strings.Repeat("f", 40)
	result := findMatches(detectors, []byte("token="+fakeCacheToken), 1024)
	if !cache.put(oid, result, false) {
		t.Fatal("result was not cacheable")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk blobCacheFile
	if err := json.Unmarshal(data[len(blobCacheMagic):], &disk); err != nil {
		t.Fatal(err)
	}
	entry := disk.Entries[oid]
	entry.Matches[0].Location = "archive/" + fakeCacheToken
	entry.Checksum = blobCacheEntryChecksum(entry)
	disk.Entries[oid] = entry
	body, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(blobCacheMagic), body...), 0600); err != nil {
		t.Fatal(err)
	}

	reopened, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
	if len(warnings) == 0 || !strings.Contains(warnings[0], "invalid entries") {
		t.Fatalf("captured-metadata warning = %v", warnings)
	}
	if _, _, ok := reopened.get(oid); ok {
		t.Fatal("entry containing a captured value was treated as a hit")
	}
}

func TestBlobCacheIsBoundedAndMergesConcurrentSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024)
	first, _ := openBlobCache(filepath.Dir(path), path, semantics, detectors, 2, 4096)
	second, _ := openBlobCache(filepath.Dir(path), path, semantics, detectors, 2, 4096)
	firstOID := strings.Repeat("1", 40)
	secondOID := strings.Repeat("2", 40)
	thirdOID := strings.Repeat("3", 40)
	if !first.put(firstOID, contentScanResult{payloads: 1}, false) || !first.put(secondOID, contentScanResult{payloads: 1}, false) {
		t.Fatal("first cache entries were not accepted")
	}
	if !second.put(thirdOID, contentScanResult{payloads: 1}, false) {
		t.Fatal("second cache entry was not accepted")
	}
	if err := first.save(); err != nil {
		t.Fatal(err)
	}
	if err := second.save(); err != nil {
		t.Fatal(err)
	}
	reopened, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 2, 4096)
	if len(warnings) != 0 {
		t.Fatalf("reopen warnings = %v", warnings)
	}
	if len(reopened.entries) != 2 {
		t.Fatalf("retained entries = %d, want bounded size 2", len(reopened.entries))
	}
	if _, _, ok := reopened.get(thirdOID); !ok {
		t.Fatal("concurrent snapshot entry was lost")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 4096 {
		t.Fatalf("cache size = %d, want <= 4096", info.Size())
	}
}

func TestBlobCacheRejectsFilesAboveConfiguredEntryLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob-cache")
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024)
	entries := map[string]blobCacheEntry{}
	for _, digit := range []string{"4", "5"} {
		oid := strings.Repeat(digit, 40)
		entry := blobCacheEntry{OID: oid, Payloads: 1}
		entry.Checksum = blobCacheEntryChecksum(entry)
		entries[oid] = entry
	}
	encoded, err := json.Marshal(blobCacheFile{
		Format: blobCacheFormat, Version: blobCacheVersion,
		Semantics: semantics, Entries: entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(blobCacheMagic), encoded...), 0600); err != nil {
		t.Fatal(err)
	}

	reopened, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 1, 1024*1024)
	if len(warnings) == 0 || !strings.Contains(warnings[0], "invalid entries") {
		t.Fatalf("entry-limit warning = %v", warnings)
	}
	if len(reopened.entries) != 0 {
		t.Fatalf("over-limit cache retained %d entries", len(reopened.entries))
	}
}

func TestBlobCacheLockContentionAndForeignFileAreSafe(t *testing.T) {
	detectors := cacheTestDetectors(t)
	semantics := cacheSemantics(detectors, 1024)
	t.Run("lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blob-cache")
		cache, _ := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
		if !cache.put(strings.Repeat("d", 40), contentScanResult{payloads: 1}, false) {
			t.Fatal("entry was not accepted")
		}
		if err := os.Mkdir(path+".lock", 0700); err != nil {
			t.Fatal(err)
		}
		if err := cache.save(); !errors.Is(err, errCacheBusy) {
			t.Fatalf("save error = %v, want busy", err)
		}
	})
	t.Run("foreign", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-cache")
		original := []byte("user data that must not be overwritten")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		cache, warnings := openBlobCache(filepath.Dir(path), path, semantics, detectors, 10, 1024*1024)
		if len(warnings) == 0 || cache.writable {
			t.Fatalf("foreign cache state: writable=%v warnings=%v", cache.writable, warnings)
		}
		if !cache.put(strings.Repeat("e", 40), contentScanResult{payloads: 1}, false) {
			t.Fatal("in-memory result was not accepted")
		}
		if err := cache.save(); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, original) {
			t.Fatal("foreign file was overwritten")
		}
	})
}

func TestScanUsesPersistentBlobCache(t *testing.T) {
	repository := makeRepo(t)
	write(t, repository, "fixture.env", "GITHUB_TOKEN="+fakeCacheToken+"\n")
	git(t, repository, "add", ".")
	commit(t, repository, "add fake cache fixture")
	cachePath := filepath.Join(repository, ".git", "reporeaper", "reporeaper-test-cache")
	options := Options{
		Version: "test", Detectors: cacheTestDetectors(t),
		Config: model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
		Cache:  CacheOptions{Enabled: true, Path: cachePath, MaxEntries: 100, MaxBytes: 1024 * 1024},
	}
	first, err := Scan(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Stats.BlobCacheMisses == 0 || first.Stats.BlobCacheHits != 0 {
		t.Fatalf("first cache stats = %#v", first.Stats)
	}
	second, err := Scan(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Stats.BlobCacheHits == 0 || second.Stats.BlobCacheMisses != 0 {
		t.Fatalf("second cache stats = %#v", second.Stats)
	}
	if !containsDetector(second, "github-token") {
		t.Fatal("cache hit did not reproduce the fake finding")
	}
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(fakeCacheToken)) {
		t.Fatal("raw fake token leaked into cached scan report")
	}
	cacheBytes, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cacheBytes, []byte(fakeCacheToken)) {
		t.Fatal("raw fake token leaked into cache file")
	}
}

func TestScanScrubsCapturedValueFromAllReportMetadataOnCacheHits(t *testing.T) {
	repository := makeRepo(t)
	branch := "branch-" + fakeCacheToken
	git(t, repository, "checkout", "-b", branch)
	filename := fakeCacheToken + ".env"
	write(t, repository, filename, "GITHUB_TOKEN="+fakeCacheToken+"\n")
	git(t, repository, "add", ".")
	git(
		t,
		repository,
		"-c", "user.name="+fakeCacheToken,
		"-c", "user.email=fixture@example.invalid",
		"commit", "-m", "add synthetic report-scrubbing fixture",
	)
	git(t, repository, "tag", "tag-"+fakeCacheToken)
	git(t, repository, "remote", "add", "remote-"+fakeCacheToken, "https://example.invalid/"+fakeCacheToken+".git")

	cachePath := filepath.Join(repository, ".git", "reporeaper", "metadata-cache")
	options := Options{
		Version: "test", Detectors: cacheTestDetectors(t),
		Config: model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
		Cache:  CacheOptions{Enabled: true, Path: cachePath, MaxEntries: 100, MaxBytes: 1024 * 1024},
	}
	first, err := Scan(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Scan(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Stats.BlobCacheHits == 0 {
		t.Fatalf("second scan did not exercise a cache hit: %#v", second.Stats)
	}
	for name, report := range map[string]model.Report{"first": first, "cached": second} {
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(fakeCacheToken)) {
			t.Fatalf("%s report serialized a captured value in metadata", name)
		}
	}
	cacheBytes, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cacheBytes, []byte(fakeCacheToken)) {
		t.Fatal("cache serialized a captured value from report metadata")
	}
}

func TestScanRejectsCacheOutsideGitDirectory(t *testing.T) {
	repository := makeRepo(t)
	write(t, repository, "fixture.txt", "safe synthetic fixture\n")
	git(t, repository, "add", ".")
	commit(t, repository, "add safe fixture")
	externalPath := filepath.Join(t.TempDir(), "untrusted-cache")
	report, err := Scan(context.Background(), repository, Options{
		Version:   "test",
		Detectors: cacheTestDetectors(t),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
		Cache:     CacheOptions{Enabled: true, Path: externalPath, MaxEntries: 100, MaxBytes: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Config.CacheEnabled || !warningContains(report.Notices, "dedicated repository Git cache directory") {
		t.Fatalf("external cache was not safely disabled: config=%#v notices=%v", report.Config, report.Notices)
	}
	if _, err := os.Stat(externalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external cache path was modified: %v", err)
	}
}

func TestScanRejectsCacheInsideGitOutsideDedicatedDirectory(t *testing.T) {
	repository := makeRepo(t)
	write(t, repository, "fixture.txt", "safe synthetic fixture\n")
	git(t, repository, "add", ".")
	commit(t, repository, "add safe fixture")
	unsafePath := filepath.Join(repository, ".git", "objects", "info", "reporeaper-cache")
	report, err := Scan(context.Background(), repository, Options{
		Version:   "test",
		Detectors: cacheTestDetectors(t),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
		Cache:     CacheOptions{Enabled: true, Path: unsafePath, MaxEntries: 100, MaxBytes: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Config.CacheEnabled || !warningContains(report.Notices, "dedicated repository Git cache directory") {
		t.Fatalf("Git-administration cache path was not rejected: config=%#v notices=%v", report.Config, report.Notices)
	}
	if _, err := os.Stat(unsafePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Git-administration path was modified: %v", err)
	}
}

func TestBlobCacheRejectsLinkedParentDirectory(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	root := filepath.Join(parent, "reporeaper")
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	path := filepath.Join(root, "blob-cache")
	detectors := cacheTestDetectors(t)
	cache, warnings := openBlobCache(root, path, cacheSemantics(detectors, 1024), detectors, 10, 1024*1024)
	if cache.writable || len(warnings) == 0 || !strings.Contains(warnings[0], "traversed a link") {
		t.Fatalf("linked cache root was accepted: writable=%v warnings=%v", cache.writable, warnings)
	}
	if !cache.put(strings.Repeat("8", 40), contentScanResult{payloads: 1}, false) {
		t.Fatal("safe in-memory result was rejected")
	}
	if err := cache.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "blob-cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("linked target was modified: %v", err)
	}
}

func TestScanResolvesRelativeCachePathInsideDedicatedDirectory(t *testing.T) {
	repository := makeRepo(t)
	write(t, repository, "fixture.txt", "safe synthetic fixture\n")
	git(t, repository, "add", ".")
	commit(t, repository, "add safe fixture")
	report, err := Scan(context.Background(), repository, Options{
		Version:   "test",
		Detectors: cacheTestDetectors(t),
		Config:    model.ScanConfig{Branches: true, Tags: true, Workers: 1, MaxFileSize: 1024 * 1024},
		Cache:     CacheOptions{Enabled: true, Path: filepath.Join("custom", "blob-cache"), MaxEntries: 100, MaxBytes: 1024 * 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Config.CacheEnabled {
		t.Fatalf("relative dedicated cache was disabled: notices=%v", report.Notices)
	}
	expected := filepath.Join(repository, ".git", "reporeaper", "custom", "blob-cache")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("relative cache was not written inside dedicated directory: %v", err)
	}
}

func cacheTestDetectors(t *testing.T) []detector.Detector {
	t.Helper()
	for _, candidate := range detector.Registry(nil, nil) {
		if candidate.ID() == "github-token" {
			return []detector.Detector{candidate}
		}
	}
	t.Fatal("github-token detector missing")
	return nil
}
