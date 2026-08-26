package agentphase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func phaseStepID(runID, traceID string, cycle uint32, phase Phase) (string, error) {
	code, ok := phaseCode(phase)
	if !ok || !uuidV7Pattern.MatchString(runID) || !uuidV7Pattern.MatchString(traceID) ||
		cycle == 0 || cycle > 8 {
		return "", newError(InvalidInput, "phase_id", "phase_identity_invalid", false, nil)
	}
	value := fmt.Sprintf("COH-AGENT-PHASE-STEP-ID-V1\x00%s\x00%s\x00%d\x00%s", runID, traceID, cycle, phase)
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	sum[15] = sum[15]&0xf8 | code
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func phaseFromStepID(value string) (Phase, error) {
	if !uuidV7Pattern.MatchString(value) {
		return "", newError(Denied, "phase_id", "step_identity_invalid", false, nil)
	}
	encoded := strings.ReplaceAll(value, "-", "")
	bytes, err := hex.DecodeString(encoded)
	if err != nil || len(bytes) != 16 {
		return "", newError(Denied, "phase_id", "step_identity_invalid", false, nil)
	}
	switch bytes[15] & 0x07 {
	case 1:
		return PlanPhase, nil
	case 2:
		return ActPhase, nil
	case 3:
		return ObservePhase, nil
	case 4:
		return ReviewPhase, nil
	default:
		return "", newError(Denied, "phase_id", "phase_code_invalid", false, nil)
	}
}

func phaseCode(value Phase) (byte, bool) {
	switch value {
	case PlanPhase:
		return 1, true
	case ActPhase:
		return 2, true
	case ObservePhase:
		return 3, true
	case ReviewPhase:
		return 4, true
	default:
		return 0, false
	}
}
