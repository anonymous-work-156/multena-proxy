package main

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapKeysToArray(t *testing.T) {
	// Test case: Map with string keys
	stringMap := map[string]int{"a": 1, "b": 2, "c": 3}
	stringKeys := mapKeysToArray(stringMap)

	// Sort the keys
	sort.Strings(stringKeys)

	expectedStringKeys := []string{"a", "b", "c"}
	assert.Equal(t, expectedStringKeys, stringKeys)

	// Test case: Map with int keys
	intMap := map[int]string{1: "a", 2: "b", 3: "c"}
	intKeys := mapKeysToArray(intMap)

	// Sort the keys
	sort.Ints(intKeys)

	expectedIntKeys := []int{1, 2, 3}
	assert.Equal(t, expectedIntKeys, intKeys)
}
