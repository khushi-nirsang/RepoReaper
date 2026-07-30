package timeline

import (
	"testing"
	"time"
)

func TestRemovalAndReintroductionCreateSeparateIntervals(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	commits := []Commit{
		{Hash: "a", Time: base},
		{Hash: "b", Parents: []string{"a"}, Time: base.Add(time.Hour)},
		{Hash: "c", Parents: []string{"b"}, Time: base.Add(2 * time.Hour)},
		{Hash: "d", Parents: []string{"c"}, Time: base.Add(3 * time.Hour)},
		{Hash: "e", Parents: []string{"d"}, Time: base.Add(4 * time.Hour)},
	}
	result := Build(commits, map[string]bool{"a": true, "b": true, "d": true}, "history-only")
	if len(result.Introductions) != 2 || result.Introductions[0] != "a" || result.Introductions[1] != "d" {
		t.Fatalf("introductions = %v", result.Introductions)
	}
	if len(result.Removals) != 2 || result.Removals[0] != "c" || result.Removals[1] != "e" {
		t.Fatalf("removals = %v", result.Removals)
	}
	if len(result.Intervals) != 2 || result.Intervals[0].RemovedBy != "c" || result.Intervals[1].RemovedBy != "e" {
		t.Fatalf("intervals = %#v", result.Intervals)
	}
}

func TestMergeMarksTimelineAmbiguous(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	commits := []Commit{
		{Hash: "root", Time: base},
		{Hash: "left", Parents: []string{"root"}, Time: base.Add(time.Hour)},
		{Hash: "right", Parents: []string{"root"}, Time: base.Add(2 * time.Hour)},
		{Hash: "merge", Parents: []string{"left", "right"}, Time: base.Add(3 * time.Hour)},
	}
	result := Build(commits, map[string]bool{"left": true, "merge": true}, "present-in-head")
	if !result.Ambiguous {
		t.Fatal("merge exposure should be marked ambiguous")
	}
	if len(result.Introductions) != 1 || result.Introductions[0] != "left" {
		t.Fatalf("introductions = %v", result.Introductions)
	}
}

func TestRemovalOnOneBranchDoesNotCloseSurvivingBranch(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	commits := []Commit{
		{Hash: "root", Time: base},
		{Hash: "removed-left", Parents: []string{"root"}, Time: base.Add(time.Hour)},
		{Hash: "right", Parents: []string{"root"}, Time: base.Add(2 * time.Hour)},
		{Hash: "right-tip", Parents: []string{"right"}, Time: base.Add(3 * time.Hour)},
	}
	result := Build(commits, map[string]bool{"root": true, "right": true, "right-tip": true}, "history-only")
	if len(result.Intervals) != 2 {
		t.Fatalf("intervals = %#v", result.Intervals)
	}
	var removed, open bool
	for _, interval := range result.Intervals {
		if interval.RemovedBy == "removed-left" && interval.EndCommit == "root" && !interval.EndedAt.IsZero() {
			removed = true
		}
		if interval.RemovedBy == "" && interval.EndCommit == "right-tip" && interval.EndedAt.IsZero() {
			open = true
		}
	}
	if !removed || !open {
		t.Fatalf("branch-specific boundaries missing: %#v", result.Intervals)
	}
}

func TestUniformMergeParentsDoNotLowerConfidence(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	commits := []Commit{
		{Hash: "root", Time: base},
		{Hash: "left", Parents: []string{"root"}, Time: base.Add(time.Hour)},
		{Hash: "right", Parents: []string{"root"}, Time: base.Add(2 * time.Hour)},
		{Hash: "merge", Parents: []string{"left", "right"}, Time: base.Add(3 * time.Hour)},
	}
	result := Build(commits, map[string]bool{"root": true, "left": true, "right": true, "merge": true}, "present-in-head")
	if result.Ambiguous {
		t.Fatal("uniformly exposed merge parents were marked ambiguous")
	}
}
