package gosdjwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertJSON2SDJWT(t *testing.T) {
	t.SkipNow()
	type have struct {
		claims map[string]any
		rules  map[string]any
	}
	tts := []struct {
		name string
		have have
		want InstructionsV2
	}{
		{
			name: "test 0",
			have: have{
				claims: map[string]any{
					"p": map[string]any{
						"k1": "v1",
					},
				},
				rules: map[string]any{},
			},
			want: InstructionsV2{
				&ParentInstructionV2{
					Name: "p",
					Children: []any{
						&ChildInstructionV2{
							Name:  "k1",
							Value: "v1",
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			instructions, err := ConvertJSON2SDJWT(tt.have.claims, tt.have.rules)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, instructions)
		})
	}
}
