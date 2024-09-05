package messages

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPrepareRoute(t *testing.T) {
	type args struct {
		input string
	}
	type want struct {
		output string
	}

	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Wrong`,
			want: want{
				output: ``,
			},
			args: args{
				input: ``,
			},
		},
		{
			name: `Ok 1`,
			want: want{
				output: `SomeText`,
			},
			args: args{
				input: `some text`,
			},
		},
		{
			name: `Ok 2`,
			want: want{
				output: `Sometext`,
			},
			args: args{
				input: `sometext`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := PrepareRoute(tt.args.input)
			require.Equal(t, tt.want.output, res)
		})
	}
}
