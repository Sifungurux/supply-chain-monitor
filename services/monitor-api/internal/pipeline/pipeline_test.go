package pipeline_test

import (
	"testing"

	"github.com/kirk-pedersen/supply-chain-monitor/monitor-api/internal/pipeline"
)

func TestTrackerStagesAndValidate(t *testing.T) {
	tr := pipeline.NewTracker([]string{"source", "build", "test", "scan", "sign", "publish", "deploy"})

	stages := tr.Stages()
	if len(stages) != 7 {
		t.Fatalf("stages = %v, want 7 entries", stages)
	}

	if err := tr.Validate("build"); err != nil {
		t.Fatalf("Validate(build) = %v, want nil", err)
	}

	if err := tr.Validate("not-a-stage"); err == nil {
		t.Fatal("expected an error for an unknown stage")
	}
}
