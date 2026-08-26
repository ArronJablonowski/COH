//go:build darwin || linux

package nativeexecutor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const helperPlanFD = 3

type helperPlan struct {
	ExecutablePath   string                      `json:"executable_path"`
	Arguments        []string                    `json:"arguments"`
	Environment      []string                    `json:"environment"`
	WorkingDirectory string                      `json:"working_directory"`
	Limits           toolregistry.ResourceLimits `json:"limits"`
}

// RunLimitHelper is the private entry point used by cmd/coh-native-limit. It
// reads one bounded plan from inherited descriptor 3, applies OS limits, and
// replaces itself with the exact staged executable. It never invokes a shell.
func RunLimitHelper() error {
	file := os.NewFile(helperPlanFD, "coh-native-plan")
	if file == nil {
		return NewError(InvalidInput, "helper_plan")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaximumInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaximumInputBytes {
		return NewError(InvalidInput, "helper_plan")
	}
	var plan helperPlan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return NewError(InvalidInput, "helper_plan")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || validateHelperPlan(plan) != nil {
		return NewError(InvalidInput, "helper_plan")
	}
	if err := os.Chdir(plan.WorkingDirectory); err != nil {
		return NewError(Unavailable, "helper_working_directory")
	}
	if err := applyPlatformIsolation(plan.Limits); err != nil {
		return err
	}
	arguments := append([]string{plan.ExecutablePath}, plan.Arguments...)
	return replaceProcess(plan.ExecutablePath, arguments, plan.Environment)
}

func validateHelperPlan(plan helperPlan) error {
	if !filepath.IsAbs(plan.ExecutablePath) || filepath.Clean(plan.ExecutablePath) != plan.ExecutablePath ||
		!filepath.IsAbs(plan.WorkingDirectory) || filepath.Clean(plan.WorkingDirectory) != plan.WorkingDirectory ||
		len(plan.Arguments) > MaximumArguments || !validLimits(plan.Limits) {
		return NewError(InvalidInput, "helper_plan")
	}
	for _, argument := range plan.Arguments {
		if argument == "" || len(argument) > MaximumArgumentBytes || strings.IndexByte(argument, 0) >= 0 {
			return NewError(InvalidInput, "helper_plan")
		}
	}
	for _, entry := range plan.Environment {
		name, _, found := strings.Cut(entry, "=")
		if !found || !envPattern.MatchString(name) || strings.IndexByte(entry, 0) >= 0 {
			return NewError(InvalidInput, "helper_plan")
		}
	}
	return nil
}
