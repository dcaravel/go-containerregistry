package registryfaker

import "strings"

// extractKVFromTag will extract 'key/values' from an image tag in the form of
// `key1-val1_key2-val2`
func extractKVFromTag(tag string) map[string]string {
	values := map[string]string{}
	allSplit := strings.Split(tag, "_") // underscore separates sets of key/value
	for _, kv := range allSplit {
		kvSplit := strings.Split(kv, "-") // dash separates key/value
		if len(kvSplit) < 2 {
			continue
		}
		k := kvSplit[0]
		v := kvSplit[1]
		values[k] = v
	}

	return values
}

// isDigest returns true if the tag represents a sha256 digest
func isDigest(tag string) bool {
	return strings.Contains(tag, "sha256")
}
