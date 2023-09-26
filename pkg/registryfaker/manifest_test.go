package registryfaker

import (
	"fmt"
	"reflect"
	"testing"
)

func TestExtractKV(t *testing.T) {
	testCases := []struct {
		tag      string
		expected map[string]string
	}{
		{
			tag: "layers-X_size-Y",
			expected: map[string]string{
				"layers": "X",
				"size":   "Y",
			},
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := extractKVFromTag(tc.tag)

			if !reflect.DeepEqual(tc.expected, got) {
				t.Errorf("expected %v but got %v", tc.expected, got)
			}
		})
	}
}
