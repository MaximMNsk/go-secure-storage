package ccrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHash(t *testing.T) {
	type args struct {
		input string
		len   int
	}
	type want struct {
		outLen int
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
			want: want{
				outLen: 8,
			},
		},
		{
			name: "GetHash2",
			args: args{
				input: "a",
				len:   16,
			},
			want: want{
				outLen: 16,
			},
		},
		{
			name: "GetHash3",
			args: args{
				input: "a",
				len:   32,
			},
			want: want{
				outLen: 32,
			},
		},
		{
			name: "GetHash4",
			args: args{
				input: "0",
				len:   32,
			},
			want: want{
				outLen: 32,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := GetHash(tt.args.input, tt.args.len)
			assert.Equal(t, tt.want.outLen, len(res))
			require.NoError(t, err)
		})
	}
}
