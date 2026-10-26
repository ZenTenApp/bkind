package policies

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestStrictSchemaCoversEveryField keeps the hand-written schema in step with Config.
// Without it, a field added to the struct is neither required by strict mode nor
// caught by the round trip — the document simply would not mention it, and an
// operator's "explicit" file would be silently incomplete.
func TestStrictSchemaCoversEveryField(t *testing.T) {
	// top level: every field of Config, except the ones that are not sections
	var topLevel []string
	for _, field := range reflect.VisibleFields(reflect.TypeOf(Config{})) {
		if field.Anonymous || !field.IsExported() {
			continue
		}
		topLevel = append(topLevel, jsonName(field))
	}
	slices.Sort(topLevel)
	want := slices.Clone(strictTopLevel)
	slices.Sort(want)
	if !slices.Equal(topLevel, want) {
		t.Fatalf("strictTopLevel is out of date:\n has %v\nwants %v (Config fields)", want, topLevel)
	}

	// sections: every field of every section struct
	for section, keys := range strictSections {
		field, ok := reflect.TypeOf(Config{}).FieldByNameFunc(func(name string) bool {
			for _, f := range reflect.VisibleFields(reflect.TypeOf(Config{})) {
				if f.Name == name && jsonName(f) == section {
					return true
				}
			}
			return false
		})
		if !ok {
			t.Fatalf("strictSections names %q, which is not a section of Config", section)
		}

		var inStruct []string
		for _, f := range reflect.VisibleFields(field.Type) {
			if !f.IsExported() {
				continue // the parsed durations
			}
			inStruct = append(inStruct, jsonName(f))
		}
		slices.Sort(inStruct)
		if have := slices.Clone(keys); !slices.Equal(sorted(have), inStruct) {
			t.Fatalf("strictSections[%q] is out of date:\n has %v\nwants %v", section, sorted(have), inStruct)
		}
	}

	// rate limits
	var inRateLimit []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(RateLimit{})) {
		if !f.IsExported() {
			continue
		}
		inRateLimit = append(inRateLimit, jsonName(f))
	}
	if !slices.Equal(sorted(inRateLimit), sorted(slices.Clone(strictRateLimitKeys))) {
		t.Fatalf("strictRateLimitKeys is out of date:\n has %v\nwants %v", strictRateLimitKeys, inRateLimit)
	}
}

// TestJSONFieldNamesAreTheSchema is the other half: the names the schema demands are
// the names the decoder will look for, so a renamed json tag cannot leave strict mode
// requiring a field that no longer exists.
func TestJSONFieldNamesAreTheSchema(t *testing.T) {
	document, err := DefaultConfig().JSON()
	if err != nil {
		t.Fatalf("failed to render: %v", err)
	}

	for _, key := range strictTopLevel {
		if !strings.Contains(string(document), `"`+key+`":`) {
			t.Fatalf("the printed document has no %q field", key)
		}
	}
	for section, keys := range strictSections {
		for _, key := range keys {
			if !strings.Contains(string(document), `"`+key+`":`) {
				t.Fatalf("the printed document has no %s.%s field", section, key)
			}
		}
	}
}

func jsonName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if index := strings.Index(tag, ","); index >= 0 {
		tag = tag[:index]
	}
	if tag == "" || tag == "-" {
		return strings.ToLower(field.Name)
	}
	return tag
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
