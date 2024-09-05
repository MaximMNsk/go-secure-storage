package ccrypt

import (
	"errors"
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

func TestGlueKeys(t *testing.T) {
	type args struct {
		pair1 []byte
		pair2 []byte
	}
	type want struct {
		result []byte
		err    error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: `Ok`,
			args: args{
				pair1: []byte("0123456789abcdef0123456789abcdef"),
				pair2: []byte("abcdef9876543210abcdef9876543210"),
			},
			want: want{
				result: []byte{81, 83, 81, 87, 81, 83, 15, 15, 15, 15,
					84, 86, 80, 86, 84, 86, 81, 83, 81, 87, 81, 83,
					15, 15, 15, 15, 84, 86, 80, 86, 84, 86},
				err: nil,
			},
		},
		{
			name: `Wrong`,
			args: args{
				pair1: []byte(""),
				pair2: []byte(""),
			},
			want: want{
				result: nil,
				err:    errors.New(`invalid keys`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := GlueKeys(tt.args.pair1, tt.args.pair2)
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.result, res)
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	type args struct {
		clearData []byte
		key       []byte
	}
	type want struct {
		errEnc error
		errDec error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: `Ok`,
			args: args{
				key:       []byte(`Some key`),
				clearData: []byte(`a`),
			},
			want: want{
				errEnc: nil,
				errDec: nil,
			},
		},
		{
			name: `Wrong`,
			args: args{
				key:       nil,
				clearData: nil,
			},
			want: want{
				errEnc: nil,
				errDec: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := Encrypt(tt.args.key, tt.args.clearData)
			require.Equal(t, tt.want.errEnc, err)

			dec, err := Decrypt(tt.args.key, enc)
			require.Equal(t, tt.want.errDec, err)

			require.Equal(t, tt.args.clearData, dec)
		})
	}
}
