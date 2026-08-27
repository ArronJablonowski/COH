package evidenceingest

import "github.com/ArronJablonowski/COH/internal/domain"

func cloneCommand(value Command) Command {
	result := value
	result.Source = cloneSource(value.Source)
	result.ParentArtifacts = append([]domain.ArtifactRef{}, value.ParentArtifacts...)
	result.ParentManifestDigests = append([]string{}, value.ParentManifestDigests...)
	result.Components = append([]ComponentVersion{}, value.Components...)
	return result
}

func cloneSource(value SourceInput) SourceInput {
	result := value
	result.SourceTime = clonePointer(value.SourceTime)
	if value.SourceRange != nil {
		copyValue := *value.SourceRange
		result.SourceRange = &copyValue
	}
	return result
}

func cloneReceipt(value Receipt) Receipt { return value }
