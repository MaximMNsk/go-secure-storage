package rand

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandStringBytes(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Not empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetString(tt.args.n)
			require.Len(t, got, tt.args.n)
		})
	}
}

func BenchmarkRandStringBytes(b *testing.B) {
	count := 10000
	b.Run(`RandStringBytes`, func(_ *testing.B) {
		for i := 0; i < count; i++ {
			_ = GetString(20)
		}
	})
}
