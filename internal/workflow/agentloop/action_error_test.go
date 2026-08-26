package agentloop

import "testing"

type classifiedActionFailure struct {
	outcome       string
	indeterminate bool
}

func (failure classifiedActionFailure) Error() string               { return "classified broker failure" }
func (failure classifiedActionFailure) ActivityOutcome() string     { return failure.outcome }
func (failure classifiedActionFailure) DispatchIndeterminate() bool { return failure.indeterminate }

func TestBrokerErrorsRemainTypedOnlyWhenDispatchDidNotStart(t *testing.T) {
	tests := []struct {
		outcome string
		step    StepStatus
		run     RunStatus
	}{
		{"denied", StepDenied, RunDenied},
		{"invalid_input", StepDenied, RunDenied},
		{"canceled", StepCanceled, RunCanceled},
		{"timeout", StepTimeout, RunTimeout},
		{"unavailable", StepFailed, RunFailed},
	}
	for _, test := range tests {
		t.Run(test.outcome, func(t *testing.T) {
			step, run, _, definitive := actionFailure(classifiedActionFailure{outcome: test.outcome})
			if !definitive || step != test.step || run != test.run {
				t.Fatalf("step=%s run=%s definitive=%v", step, run, definitive)
			}
		})
	}
	if _, _, _, definitive := actionFailure(classifiedActionFailure{outcome: "timeout", indeterminate: true}); definitive {
		t.Fatal("indeterminate dispatch was classified as a safe terminal timeout")
	}
}
