package gosdjwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardPresentationString(t *testing.T) {
	tts := []struct {
		name string
		have StandardPresentation
		want string
	}{
		{
			name: "test 0",
			have: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: nil,
				KeyBinding:  "",
			},
			want: "xx.xxx.xxx",
		},
		{
			name: "test 1",
			have: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: []string{"d1"},
				KeyBinding:  "",
			},
			want: "xx.xxx.xxx~d1~",
		},
		{
			name: "test 2",
			have: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: []string{"d1", "d2"},
				KeyBinding:  "",
			},
			want: "xx.xxx.xxx~d1~d2~",
		},
		{
			name: "test 3",
			have: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: []string{"d1"},
				KeyBinding:  "kb",
			},
			want: "xx.xxx.xxx~d1~kb",
		},
		{
			name: "test 4",
			have: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: nil,
				KeyBinding:  "kb",
			},
			want: "xx.xxx.xxxkb",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.have.String()
			assert.Equal(t, tt.want, got)
		})
	}
}
