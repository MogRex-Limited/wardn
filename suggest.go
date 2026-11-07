package wardn

import "slices"

// suggest returns the candidate closest to name, for "did you mean ...?"
// messages, or "" if no candidate is close enough to be a likely typo.
// Ties are broken alphabetically so messages are deterministic.
func suggest(name string, candidates []string) string {
	if name == "" || len(name) > maxPermissionLen {
		return ""
	}
	sorted := slices.Clone(candidates)
	slices.Sort(sorted)

	best, bestDist := "", -1
	for _, c := range sorted {
		if c == name || len(c) > maxPermissionLen {
			continue
		}
		d := editDistance(name, c)
		if bestDist == -1 || d < bestDist {
			best, bestDist = c, d
		}
	}
	if bestDist == -1 || bestDist > max(2, len(name)/4) || bestDist >= len(name) {
		return ""
	}
	return best
}

// editDistance is the Optimal String Alignment distance: the number of
// single-byte insertions, deletions, substitutions and adjacent
// transpositions needed to turn a into b. Names are ASCII, so bytes suffice.
func editDistance(a, b string) int {
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(b)]
}
