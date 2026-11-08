// Package schemas holds the JSON Schemas of the A2H 1.0 messages and
// validates documents against them.
package schemas

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed a2h-1.0.schema.json
var schemaJSON []byte

// ID is the $id of the schema document.
const ID = "https://raw.githubusercontent.com/AndreaAcanfora/a2h-gateway/master/schemas/a2h-1.0.schema.json"

var (
	once     sync.Once
	compiler *jsonschema.Compiler
	cache    sync.Map
	initErr  error
)

// Definitions lists the message definitions under $defs that documents can be checked against.
var Definitions = []string{"Message", "Response", "ErrorMessage", "ErrorResponse", "IntentResponse", "InteractionStatus", "Capabilities"}

// Validate checks a JSON document against a definition, e.g. "Response".
func Validate(definition string, document []byte) error {
	once.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			initErr = err
			return
		}
		compiler = jsonschema.NewCompiler()
		compiler.AssertFormat()
		initErr = compiler.AddResource(ID, doc)
	})
	if initErr != nil {
		return initErr
	}
	s, ok := cache.Load(definition)
	if !ok {
		compiled, err := compiler.Compile(ID + "#/$defs/" + definition)
		if err != nil {
			return fmt.Errorf("schemas: %w", err)
		}
		s, _ = cache.LoadOrStore(definition, compiled)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("schemas: invalid JSON: %w", err)
	}
	return s.(*jsonschema.Schema).Validate(inst)
}
