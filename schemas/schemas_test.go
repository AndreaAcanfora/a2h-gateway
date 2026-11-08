package schemas

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Example files are named <Definition>.<case>.json.
func examples(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("examples", dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples in %s", dir)
	}
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = b
	}
	return out
}

func definition(name string) string { return strings.SplitN(name, ".", 2)[0] }

func TestValidExamples(t *testing.T) {
	for name, doc := range examples(t, "valid") {
		if err := Validate(definition(name), doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInvalidExamples(t *testing.T) {
	for name, doc := range examples(t, "invalid") {
		if err := Validate(definition(name), doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEveryDefinitionCompiles(t *testing.T) {
	for _, d := range Definitions {
		if err := Validate(d, []byte(`{}`)); err != nil && strings.HasPrefix(err.Error(), "schemas:") {
			t.Errorf("%s: %v", d, err)
		}
	}
	if err := Validate("Nope", []byte(`{}`)); err == nil {
		t.Error("unknown definition accepted")
	}
}
