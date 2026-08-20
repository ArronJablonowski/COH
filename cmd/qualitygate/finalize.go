package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/quality"
)

func finalizeRunEvidence(
	ctx context.Context,
	root, artifactDirectory, reportPath string,
	report *quality.Report,
	runErr error,
) error {
	if err := quality.WriteReportAtomic(reportPath, report); err != nil {
		return err
	}
	if err := verifyPersistedReport(reportPath, *report); err != nil {
		_ = os.Remove(reportPath)
		return err
	}
	if runErr != nil {
		return finalizeFailureEvidence(artifactDirectory, reportPath, *report, runErr)
	}
	if err := quality.CheckContext(ctx, "finalization"); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.VerifyEvidenceBundle(root, artifactDirectory, reportPath, *report); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	report.QualityGatePromotable = report.Lane.Enforcement == "required" &&
		report.Provenance.VCSRevision != "unborn" && !report.Provenance.VCSModified
	if err := quality.CheckContext(ctx, "finalization"); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.WriteReportAtomic(reportPath, report); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := verifyPersistedReport(reportPath, *report); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	manifestPath := filepath.Join(artifactDirectory, "evidence-manifest.json")
	if _, err := quality.WriteEvidenceManifestAtomic(ctx, artifactDirectory, manifestPath); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.SyncEvidenceBundle(artifactDirectory); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.CheckContext(ctx, "finalization"); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.VerifyEvidenceManifest(artifactDirectory, manifestPath); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	publicationPath := filepath.Join(artifactDirectory, "publication-manifest.json")
	if err := quality.WritePublicationManifestAtomic(
		artifactDirectory, publicationPath, report.QualityGatePromotable,
	); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.SyncEvidenceBundle(artifactDirectory); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	if err := quality.CheckContext(ctx, "finalization"); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	publicDirectory := artifactDirectory + ".public"
	if err := quality.PublishPublicBundleAtomic(ctx, artifactDirectory, publicDirectory); err != nil {
		invalidateSuccessfulEvidence(reportPath, artifactDirectory)
		return err
	}
	return nil
}

func finalizeFailureEvidence(artifactDirectory, reportPath string, report quality.Report, runErr error) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manifestPath := filepath.Join(artifactDirectory, "failure-manifest.json")
	if err := quality.WriteFailureManifestAtomic(cleanupContext, artifactDirectory, manifestPath, report); err != nil {
		_ = os.Remove(reportPath)
		_ = os.Remove(manifestPath)
		return errors.Join(runErr, err)
	}
	if err := quality.SyncEvidenceBundle(artifactDirectory); err != nil {
		_ = os.Remove(reportPath)
		_ = os.Remove(manifestPath)
		return errors.Join(runErr, err)
	}
	if err := quality.VerifyFailureManifest(artifactDirectory, manifestPath); err != nil {
		_ = os.Remove(reportPath)
		_ = os.Remove(manifestPath)
		return errors.Join(runErr, err)
	}
	return runErr
}

func verifyPersistedReport(path string, report quality.Report) error {
	diskReport, err := quality.ReadAndVerifyReport(path)
	if err != nil || diskReport.ReportDigest != report.ReportDigest {
		return errors.Join(err, errors.New("report read-back mismatch"))
	}
	return nil
}

func invalidateSuccessfulEvidence(reportPath, artifactDirectory string) {
	_ = os.Remove(filepath.Join(artifactDirectory, "evidence-manifest.json"))
	_ = os.Remove(filepath.Join(artifactDirectory, "publication-manifest.json"))
	_ = os.Remove(filepath.Join(artifactDirectory, "failure-manifest.json"))
	_ = os.Remove(reportPath)
	_ = os.RemoveAll(artifactDirectory + ".public")
}
