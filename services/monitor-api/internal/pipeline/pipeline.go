package pipeline

import "fmt"

// Tracker knows the ordered list of valid pipeline stages for this
// deployment (configured via the PIPELINE_STAGES env var / ConfigMap)
// and validates stage-transition requests against it.
type Tracker struct {
	stages []string
	index  map[string]int
}

func NewTracker(stages []string) *Tracker {
	idx := make(map[string]int, len(stages))
	for i, s := range stages {
		idx[s] = i
	}
	return &Tracker{stages: stages, index: idx}
}

func (t *Tracker) Stages() []string {
	return t.stages
}

func (t *Tracker) Validate(stage string) error {
	if _, ok := t.index[stage]; !ok {
		return fmt.Errorf("unknown pipeline stage %q, expected one of %v", stage, t.stages)
	}
	return nil
}
