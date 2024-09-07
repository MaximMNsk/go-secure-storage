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

func TestNewMessage(t *testing.T) {
	type args struct {
		typ     string
		content string
		message string
	}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{
				typ:     ``,
				content: ``,
				message: ``,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := NewMessage(tt.args.typ, tt.args.content, tt.args.message)
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetExitRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Exit`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetExitRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetStartRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Start`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetStartRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetRegisterRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Register`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetRegisterRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetLoginRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Login`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetLoginRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetLogoutRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Logout`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetLogoutRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetPrimaryRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `Primary`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetPrimaryRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetShowCardsRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `ShowCards`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetShowCardsRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetAddCardRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `AddCard`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetAddCardRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetShowCredentialsRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `ShowCredentials`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetShowCredentialsRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetAddCredentialsRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `AddCredentials`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetAddCredentialsRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetShowPlainsRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `ShowPlains`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetShowPlainsRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetAddPlainRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `AddPlain`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetAddPlainRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetShowFilesRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `ShowFiles`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetShowFilesRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}

func TestMessage_GetAddFileRoute(t *testing.T) {
	type args struct{}
	type want struct {
		mess Message
	}
	tests := []struct {
		name string
		want want
		args args
	}{
		{
			name: `Ok`,
			args: args{},
			want: want{
				mess: Message{
					Type:    `route`,
					Content: `AddFile`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mess := new(Message)
			res := mess.GetAddFileRoute()
			require.Equal(t, tt.want.mess, res)
		})
	}
}
