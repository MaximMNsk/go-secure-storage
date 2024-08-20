package ccrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHash(t *testing.T) {
	type args struct {
		input string
		len   int
	}
	type want struct {
		output string
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "GetHash1",
			args: args{
				input: "a",
				len:   8,
			},
		},
		{
			name: "GetHash2",
			args: args{
				input: "a",
				len:   16,
			},
		},
		{
			name: "GetHash2",
			args: args{
				input: "a",
				len:   32,
			},
		},
		{
			name: "GetHash2",
			args: args{
				input: "",
				len:   32,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := GetHash(tt.args.input, tt.args.len)
			t.Log(res)
			require.NoError(t, err)
		})
	}
}
