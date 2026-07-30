package model

import "time"

const (
	SchemaVersion                  = "1.1"
	LegacySchemaVersion            = "1.0"
	ScanReportDocumentType         = "scan-report"
	VerificationResultDocumentType = "verification-result"
)

func IsSupportedSchema(version string) bool {
	return version == SchemaVersion || version == LegacySchemaVersion
}

type Severity string
type Confidence string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"

	ConfidenceUncertain Confidence = "uncertain"
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

type Report struct {
	DocumentType  string     `json:"document_type,omitempty"`
	SchemaVersion string     `json:"schema_version"`
	ToolVersion   string     `json:"tool_version"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Config        ScanConfig `json:"scan_config"`
	Repository    Repository `json:"repository"`
	Findings      []Finding  `json:"findings"`
	Summary       Summary    `json:"summary"`
	Stats         ScanStats  `json:"stats"`
	Warnings      []string   `json:"warnings,omitempty"`
	Notices       []string   `json:"notices,omitempty"`
}

type ScanConfig struct {
	IncludeUntracked   bool              `json:"include_untracked"`
	Branches           bool              `json:"branches"`
	Tags               bool              `json:"tags"`
	AllRefs            bool              `json:"all_refs"`
	Unreachable        bool              `json:"unreachable"`
	Reflogs            bool              `json:"reflogs"`
	Workers            int               `json:"workers"`
	MaxFileSize        int64             `json:"max_file_size"`
	Severity           []string          `json:"severity,omitempty"`
	Detectors          []string          `json:"detectors,omitempty"`
	DetectorSignatures map[string]string `json:"detector_signatures,omitempty"`
	Since              string            `json:"since,omitempty"`
	Until              string            `json:"until,omitempty"`
	CacheEnabled       bool              `json:"cache_enabled"`
}

type Repository struct {
	Path       string   `json:"path"`
	GitDir     string   `json:"git_dir"`
	Bare       bool     `json:"bare"`
	Head       string   `json:"head,omitempty"`
	Branch     string   `json:"branch,omitempty"`
	Remotes    []Remote `json:"remotes,omitempty"`
	Shallow    bool     `json:"shallow"`
	WorktreeOK bool     `json:"worktree_ok"`
	IndexOK    bool     `json:"index_ok"`
}

type Remote struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Finding struct {
	ID                      string             `json:"id"`
	DetectorID              string             `json:"detector_id"`
	DetectorName            string             `json:"detector_name"`
	Category                string             `json:"category"`
	Severity                Severity           `json:"severity"`
	Confidence              Confidence         `json:"confidence"`
	ConfidenceReason        string             `json:"confidence_reason"`
	RiskScore               int                `json:"risk_score"`
	RiskExplanation         string             `json:"risk_explanation"`
	Fingerprint             string             `json:"fingerprint"`
	ShortFingerprint        string             `json:"short_fingerprint"`
	Redacted                string             `json:"redacted"`
	CurrentStatus           string             `json:"current_status"`
	InWorkingTree           bool               `json:"in_working_tree"`
	InTrackedWorkingTree    bool               `json:"in_tracked_working_tree"`
	InUntracked             bool               `json:"in_untracked_file"`
	InHead                  bool               `json:"in_head"`
	InIndex                 bool               `json:"in_index"`
	InDirectRef             bool               `json:"in_direct_ref_object"`
	InReflog                bool               `json:"in_reflog"`
	InUnreachable           bool               `json:"in_unreachable_objects"`
	CommitCount             int                `json:"commit_count"`
	ExposureDurationSeconds int64              `json:"estimated_exposure_duration_seconds"`
	RemoteStatus            string             `json:"remote_status"`
	RemoteReason            string             `json:"remote_reason"`
	FirstSeen               *Evidence          `json:"first_seen,omitempty"`
	LastSeen                *Evidence          `json:"last_seen,omitempty"`
	Introduced              *Evidence          `json:"introduced,omitempty"`
	Removed                 *Evidence          `json:"removed,omitempty"`
	ExposureIntervals       []ExposureInterval `json:"exposure_intervals,omitempty"`
	Evidence                []Evidence         `json:"evidence"`
	Paths                   []string           `json:"paths"`
	Branches                []string           `json:"branches,omitempty"`
	Tags                    []string           `json:"tags,omitempty"`
	Remediation             []string           `json:"remediation"`
}

type ExposureInterval struct {
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at,omitempty"`
	StartCommit string    `json:"start_commit,omitempty"`
	EndCommit   string    `json:"end_commit,omitempty"`
	RemovedBy   string    `json:"removed_by,omitempty"`
	Status      string    `json:"status"`
}

type Evidence struct {
	Source      string    `json:"source"`
	Commit      string    `json:"commit,omitempty"`
	Blob        string    `json:"blob,omitempty"`
	Path        string    `json:"path,omitempty"`
	Line        int       `json:"line,omitempty"`
	Ref         string    `json:"ref,omitempty"`
	AuthorName  string    `json:"author_name,omitempty"`
	AuthorEmail string    `json:"author_email,omitempty"`
	Time        time.Time `json:"time,omitempty"`
	Unreachable bool      `json:"unreachable,omitempty"`
	Reflog      bool      `json:"reflog,omitempty"`
	InHead      bool      `json:"in_head,omitempty"`
	Untracked   bool      `json:"untracked,omitempty"`
	Decoder     string    `json:"decoder,omitempty"`
}

type Summary struct {
	FindingsBySeverity  map[Severity]int `json:"findings_by_severity"`
	CurrentSecrets      int              `json:"current_secrets"`
	HistoricalSecrets   int              `json:"historical_secrets"`
	UnreachableSecrets  int              `json:"unreachable_object_secrets"`
	SuppressedFindings  int              `json:"suppressed_findings"`
	AllowlistSuppressed int              `json:"allowlist_suppressed"`
	BaselineSuppressed  int              `json:"baseline_suppressed"`
}

type ScanStats struct {
	DurationMillis    int64 `json:"duration_millis"`
	ObjectsScanned    int   `json:"objects_scanned"`
	ObjectsSkipped    int   `json:"objects_skipped"`
	BlobsDeduplicated int   `json:"blobs_deduplicated"`
	CommitsAnalyzed   int   `json:"commits_analyzed"`
	PayloadsScanned   int   `json:"payloads_scanned"`
	ArchivesOpened    int   `json:"archives_opened"`
	EncodedPayloads   int   `json:"encoded_payloads_scanned"`
	BytesInspected    int64 `json:"bytes_inspected"`
	TreesRead         int   `json:"trees_read"`
	TreeCacheHits     int   `json:"tree_cache_hits"`
	BlobCacheHits     int   `json:"blob_cache_hits"`
	BlobCacheMisses   int   `json:"blob_cache_misses"`
}
