package agentphase

import (
	"context"
	"errors"
)

type SideEffectState string

const (
	SideEffectNone      SideEffectState = "none"
	SideEffectConfirmed SideEffectState = "confirmed"
	SideEffectUncertain SideEffectState = "uncertain"
)

type CandidateArtifact struct {
	ArtifactDigest string          `json:"artifact_digest"`
	Text           string          `json:"text,omitempty"`
	Workspace      string          `json:"workspace"`
	SideEffect     SideEffectState `json:"side_effect"`
}

type GenerationRequest struct {
	Attempt         uint32
	Contract        TaskContract
	Profile         ModelExecutionProfile
	Prompt          CompiledPrompt
	UserPrompt      string
	PriorArtifact   string
	PriorValidation string
}

type AttemptGenerator interface {
	Generate(context.Context, GenerationRequest) (CandidateArtifact, string, error)
}

type ArtifactValidator interface {
	ID() string
	Digest() string
	Validate(context.Context, TaskContract, CandidateArtifact, uint32, string, string) (ValidationRecordV2, error)
}

type RepairResult struct {
	Accepted         bool                 `json:"accepted"`
	Incomplete       bool                 `json:"incomplete"`
	Calls            uint32               `json:"calls"`
	Artifact         CandidateArtifact    `json:"artifact"`
	Validations      []ValidationRecordV2 `json:"validations"`
	ProvenanceDigest string               `json:"provenance_digest"`
}

type RepairController struct {
	generator AttemptGenerator
	validator ArtifactValidator
}

func NewRepairController(generator AttemptGenerator, validator ArtifactValidator) (*RepairController, error) {
	if generator == nil || validator == nil || !validToken(validator.ID()) || !validDigest(validator.Digest()) {
		return nil, errors.New("repair controller dependencies are invalid")
	}
	return &RepairController{generator: generator, validator: validator}, nil
}

func (controller *RepairController) Run(ctx context.Context, contract TaskContract,
	profile ModelExecutionProfile) (RepairResult, error) {
	if controller == nil || controller.generator == nil || controller.validator == nil {
		return RepairResult{}, errors.New("repair controller is unavailable")
	}
	prompt, err := CompilePrompt(contract, profile)
	if err != nil {
		return RepairResult{}, err
	}
	result := RepairResult{Validations: []ValidationRecordV2{}}
	userPrompt, previousArtifact, previousValidation := prompt.UserPrompt, "", ""
	for attempt := uint32(1); attempt <= contract.Repair.MaximumModelCalls; attempt++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		candidate, budget, generateErr := controller.generator.Generate(ctx, GenerationRequest{Attempt: attempt,
			Contract: contract, Profile: profile, Prompt: prompt, UserPrompt: userPrompt,
			PriorArtifact: previousArtifact, PriorValidation: previousValidation})
		if generateErr != nil {
			return result, generateErr
		}
		if !validDigest(candidate.ArtifactDigest) || !validDigest(budget) || candidate.Workspace != contract.Workspace ||
			candidate.SideEffect != SideEffectNone && candidate.SideEffect != SideEffectConfirmed && candidate.SideEffect != SideEffectUncertain {
			return result, errors.New("generator returned an invalid candidate binding")
		}
		record, validateErr := controller.validator.Validate(ctx, contract, candidate, attempt, budget, previousValidation)
		if validateErr != nil {
			return result, validateErr
		}
		if err := record.Validate(); err != nil || record.ArtifactDigest != candidate.ArtifactDigest ||
			record.ValidatorID != controller.validator.ID() || record.ValidatorDigest != controller.validator.Digest() {
			return result, errors.New("validator returned an invalid record binding")
		}
		result.Calls, result.Artifact = attempt, candidate
		result.Validations = append(result.Validations, record)
		result.ProvenanceDigest = canonicalDigest(result.Validations)
		if record.Disposition == ValidationAccepted {
			result.Accepted = true
			return result, nil
		}
		if candidate.SideEffect != SideEffectNone {
			return result, errors.New("repair denied after a confirmed or uncertain side effect")
		}
		if attempt == contract.Repair.MaximumModelCalls {
			result.Incomplete = !contract.SecuritySensitive
			return result, nil
		}
		userPrompt, err = CompileRepairPrompt(prompt, record)
		if err != nil {
			return result, err
		}
		previousArtifact, previousValidation = candidate.ArtifactDigest, record.ProvenanceDigest
	}
	return result, nil
}
