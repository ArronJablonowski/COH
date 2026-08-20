package quality

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type govulnSARIF struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string `json:"name"`
				SemanticVersion string `json:"semanticVersion"`
				Properties      struct {
					ScannerName    string `json:"scanner_name"`
					ScannerVersion string `json:"scanner_version"`
					Database       string `json:"db"`
					DBModified     string `json:"db_last_modified"`
					ScanLevel      string `json:"scan_level"`
					ScanMode       string `json:"scan_mode"`
				} `json:"properties"`
			} `json:"driver"`
		} `json:"tool"`
		Results []json.RawMessage `json:"results"`
	} `json:"runs"`
}

func VerifyGovulnSARIF(path, databaseURL, modified string) error {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return err
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return qualityError(CodeInvalidInput, "govuln_sarif", "duplicate or invalid JSON member", err)
	}
	var report govulnSARIF
	if err := json.Unmarshal(data, &report); err != nil {
		return qualityError(CodeInvalidInput, "govuln_sarif", "invalid SARIF", err)
	}
	if report.Version != "2.1.0" || len(report.Runs) != 1 {
		return qualityError(CodeDenied, "govuln_sarif", "unexpected SARIF run contract", nil)
	}
	driver := report.Runs[0].Tool.Driver
	if driver.Name != "govulncheck" || driver.SemanticVersion != "v1.7.0" ||
		driver.Properties.ScannerName != "govulncheck" || driver.Properties.ScannerVersion != "v1.7.0" ||
		driver.Properties.Database != databaseURL || driver.Properties.DBModified != modified ||
		driver.Properties.ScanLevel != "symbol" || driver.Properties.ScanMode != "source" {
		return qualityError(CodeDenied, "govuln_sarif", "scanner or database provenance mismatch", nil)
	}
	if report.Runs[0].Results == nil {
		return qualityError(CodeDenied, "govuln_sarif", "explicit results array is required", nil)
	}
	if len(report.Runs[0].Results) != 0 {
		return qualityError(CodeDenied, "govuln_sarif", "vulnerability findings deny the gate", nil)
	}
	return nil
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return err
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate object member")
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected closing delimiter")
	}
}
