package architecturecatalog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func ValidateDirectory(directory string) error {
	for _, catalogType := range catalogTypes {
		path := filepath.Join(directory, catalogType+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > MaximumBytes {
			return fmt.Errorf("catalog exceeds publication bound")
		}
		var catalog Catalog
		if err := decodeStrict(data, &catalog); err != nil {
			return err
		}
		if catalog.SchemaVersion != SchemaVersion || catalog.ContractVersion != ContractVersion ||
			catalog.CatalogType != catalogType || !equalStrings(catalog.Requirements, requirements) ||
			len(catalog.Sources) == 0 || len(catalog.Records) > 131072 {
			return fmt.Errorf("catalog %s violates closed schema", catalogType)
		}
		for index, source := range catalog.Sources {
			if source.Path == "" || source.Version == "" || len(source.Digest) != 71 ||
				index > 0 && catalog.Sources[index-1].Path >= source.Path {
				return fmt.Errorf("catalog %s has invalid sources", catalogType)
			}
		}
		for index, record := range catalog.Records {
			if unsafeRecord(record) || index > 0 && recordKey(catalog.Records[index-1]) >= recordKey(record) {
				return fmt.Errorf("catalog %s has invalid records", catalogType)
			}
			if !sort.SliceIsSorted(record.Attributes, func(a, b int) bool { return record.Attributes[a].Name < record.Attributes[b].Name }) {
				return fmt.Errorf("catalog %s has unsorted attributes", catalogType)
			}
		}
		encoded, err := canonical(catalog)
		if err != nil || !bytes.Equal(encoded, data) {
			return fmt.Errorf("catalog %s digest or canonical bytes differ", catalogType)
		}
	}
	return nil
}

func recordKey(record Record) string { return record.Kind + "\x00" + record.ID }

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
