package main

import (
	"os"
	"path/filepath"
)

func mapKeysToArray[K comparable, V any](tenantLabel map[K]V) []K {
	tenantLabelKeys := make([]K, 0, len(tenantLabel))
	for key := range tenantLabel {
		tenantLabelKeys = append(tenantLabelKeys, key)
	}
	return tenantLabelKeys
}

func tryReadFile(path string) ([]byte, error) {
	filename, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return yamlFile, nil
}
