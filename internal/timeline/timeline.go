package timeline

import (
	"sort"
	"time"

	"github.com/khushi/reporeaper/internal/model"
)

type Commit struct {
	Hash    string
	Parents []string
	Time    time.Time
}

type Result struct {
	Introductions []string
	Removals      []string
	Intervals     []model.ExposureInterval
	Ambiguous     bool
}

// Build derives graph-aware exposure boundaries from commit snapshot membership.
// A merge is considered exposed when the resulting merge tree contains the value,
// regardless of which parent supplied it.
func Build(commits []Commit, present map[string]bool, currentStatus string) Result {
	byHash := make(map[string]Commit, len(commits))
	children := make(map[string][]string, len(commits))
	for _, c := range commits {
		byHash[c.Hash] = c
		for _, p := range c.Parents {
			children[p] = append(children[p], c.Hash)
		}
	}

	var result Result
	removalSet := map[string]bool{}
	for _, c := range commits {
		if present[c.Hash] {
			hasPresentParent := false
			for _, p := range c.Parents {
				hasPresentParent = hasPresentParent || present[p]
			}
			if !hasPresentParent {
				result.Introductions = append(result.Introductions, c.Hash)
			}
		} else {
			for _, p := range c.Parents {
				if present[p] {
					removalSet[c.Hash] = true
					break
				}
			}
		}
		if mergePresenceDiffers(c, present) {
			result.Ambiguous = true
		}
	}
	for removal := range removalSet {
		result.Removals = append(result.Removals, removal)
	}
	sortCommitHashes(result.Removals, byHash)
	for _, intro := range result.Introductions {
		result.Intervals = append(result.Intervals, intervalsFromIntroduction(intro, byHash, children, present, currentStatus)...)
	}
	sort.SliceStable(result.Intervals, func(i, j int) bool {
		if result.Intervals[i].StartedAt.Equal(result.Intervals[j].StartedAt) {
			if result.Intervals[i].StartCommit != result.Intervals[j].StartCommit {
				return result.Intervals[i].StartCommit < result.Intervals[j].StartCommit
			}
			if result.Intervals[i].EndedAt.Equal(result.Intervals[j].EndedAt) {
				if result.Intervals[i].RemovedBy != result.Intervals[j].RemovedBy {
					return result.Intervals[i].RemovedBy < result.Intervals[j].RemovedBy
				}
				return result.Intervals[i].EndCommit < result.Intervals[j].EndCommit
			}
			if result.Intervals[i].EndedAt.IsZero() {
				return false
			}
			if result.Intervals[j].EndedAt.IsZero() {
				return true
			}
			return result.Intervals[i].EndedAt.Before(result.Intervals[j].EndedAt)
		}
		return result.Intervals[i].StartedAt.Before(result.Intervals[j].StartedAt)
	})
	return result
}

type exposureBoundary struct {
	removed     string
	lastPresent string
}

func intervalsFromIntroduction(start string, commits map[string]Commit, children map[string][]string, present map[string]bool, currentStatus string) []model.ExposureInterval {
	queue := []string{start}
	seen := map[string]bool{start: true}
	boundaries := map[string]exposureBoundary{}
	openTips := map[string]bool{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		childCommits := children[cur]
		if len(childCommits) == 0 {
			openTips[cur] = true
		}
		for _, child := range childCommits {
			if present[child] && !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			} else if !present[child] {
				candidate := exposureBoundary{removed: child, lastPresent: cur}
				existing, exists := boundaries[child]
				if !exists || laterCommit(cur, existing.lastPresent, commits) {
					boundaries[child] = candidate
				}
			}
		}
	}
	startCommit := commits[start]
	var intervals []model.ExposureInterval
	removals := make([]string, 0, len(boundaries))
	for removal := range boundaries {
		removals = append(removals, removal)
	}
	sortCommitHashes(removals, commits)
	for _, removal := range removals {
		boundary := boundaries[removal]
		removedCommit := commits[removal]
		intervals = append(intervals, model.ExposureInterval{
			StartedAt: startCommit.Time, EndedAt: removedCommit.Time,
			StartCommit: start, EndCommit: boundary.lastPresent,
			RemovedBy: removal, Status: "removed-from-snapshot",
		})
	}
	tips := make([]string, 0, len(openTips))
	for tip := range openTips {
		tips = append(tips, tip)
	}
	sortCommitHashes(tips, commits)
	for _, tip := range tips {
		intervals = append(intervals, model.ExposureInterval{
			StartedAt: startCommit.Time, StartCommit: start,
			EndCommit: tip, Status: currentStatus,
		})
	}
	if len(intervals) == 0 {
		intervals = append(intervals, model.ExposureInterval{
			StartedAt: startCommit.Time, StartCommit: start, EndCommit: start, Status: currentStatus,
		})
	}
	return intervals
}

func mergePresenceDiffers(commit Commit, present map[string]bool) bool {
	if len(commit.Parents) < 2 {
		return false
	}
	first := present[commit.Parents[0]]
	for _, parent := range commit.Parents[1:] {
		if present[parent] != first {
			return true
		}
	}
	return false
}

func laterCommit(candidate, existing string, commits map[string]Commit) bool {
	a, b := commits[candidate], commits[existing]
	if a.Time.Equal(b.Time) {
		return a.Hash > b.Hash
	}
	return a.Time.After(b.Time)
}

func sortCommitHashes(hashes []string, commits map[string]Commit) {
	sort.Slice(hashes, func(i, j int) bool {
		a, b := commits[hashes[i]], commits[hashes[j]]
		if a.Time.Equal(b.Time) {
			return a.Hash < b.Hash
		}
		return a.Time.Before(b.Time)
	})
}
