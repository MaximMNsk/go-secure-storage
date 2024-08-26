package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/MaximMNsk/go-secure-storage/internal/cjwt"
	pb "github.com/MaximMNsk/go-secure-storage/proto"
	miniomock "github.com/MaximMNsk/go-secure-storage/server/storage/minio/mocks"
	pgmock "github.com/MaximMNsk/go-secure-storage/server/storage/postgres/mocks"
)

func TestSecureStorageServer_RegisterUser(t *testing.T) {
	type saver struct {
		uid       int
		duplicate bool
		err       error
	}
	type args struct {
		in    *pb.RegisterUserRequest
		saver saver
	}
	type want struct {
		out *pb.RegisterUserResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				in: &pb.RegisterUserRequest{
					Login:    `login`,
					Password: `password`,
					User: &pb.User{
						Name:       "name",
						SecondName: "second name",
					},
				},
				saver: saver{uid: 10, duplicate: false, err: nil},
			},
			want: want{
				out: &pb.RegisterUserResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "duplicate",
			args: args{
				in: &pb.RegisterUserRequest{
					Login:    `login`,
					Password: `password`,
					User: &pb.User{
						Name:       "name",
						SecondName: "second name",
					},
				},
				saver: saver{uid: -1, duplicate: true, err: nil},
			},
			want: want{
				out: &pb.RegisterUserResponse{
					Answer: pb.Answer_AlreadyExists,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbMock := pgmock.NewPGStorage(t)

			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			dbMock.
				On(`GetUserKeyByLogin`, mock.Anything, mock.Anything).
				Return([]byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`), nil)
			dbMock.
				On(`SaveUser`, context.Background(), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(tt.args.saver.uid, tt.args.saver.duplicate, tt.args.saver.err)

			s.DB = dbMock
			s.EncryptedMasterKey = []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149,
				157, 48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
				242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57}

			resp, err := s.RegisterUser(context.Background(), tt.args.in)
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
			if tt.name == `success` {
				require.NotEmpty(t, resp.Token)
			}
		})
	}
}

func TestSecureStorageServer_AuthUser(t *testing.T) {
	type getter struct {
		id      int
		creds   string
		pwdHash string
		err     error
	}
	type args struct {
		in         *pb.AuthUserRequest
		mockGetter getter
	}
	type want struct {
		out *pb.AuthUserResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				in: &pb.AuthUserRequest{
					Login:    `login`,
					Password: `zxc`,
				},
				mockGetter: getter{
					id:      1,
					creds:   ``,
					pwdHash: `5fa72358f0b4fb4f`,
					err:     nil,
				},
			},
			want: want{
				out: &pb.AuthUserResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "incorrect",
			args: args{
				in: &pb.AuthUserRequest{
					Login:    `login`,
					Password: `zxcccccc`,
				},
				mockGetter: getter{
					id:      1,
					creds:   ``,
					pwdHash: `5fa72358f0b4fb4f`,
					err:     nil,
				},
			},
			want: want{
				out: &pb.AuthUserResponse{
					Answer: pb.Answer_IncorrectPwd,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbMock := pgmock.NewPGStorage(t)

			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			dbMock.
				On(`GetUserByLogin`, context.Background(), tt.args.in.Login).
				Return(tt.args.mockGetter.id, tt.args.mockGetter.creds, tt.args.mockGetter.pwdHash, tt.args.mockGetter.err)

			s.DB = dbMock
			s.EncryptedMasterKey = []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157, 48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206, 242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57}

			resp, err := s.AuthUser(context.Background(), tt.args.in)
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
			if tt.name == `success` {
				require.NotEmpty(t, resp.Token)
			}
		})
	}
}

func TestSecureStorageServer_CheckService(t *testing.T) {
	type args struct {
		token string
		uid   string
	}
	type want struct {
		out *pb.CheckServiceResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "unauthorized",
			args: args{
				token: ``,
				uid:   `-1`,
			},
			want: want{
				out: &pb.CheckServiceResponse{
					Answer: pb.Answer_UnauthorizedUser,
					Up:     false,
				},
				err: nil,
			},
		},
		{
			name: "success",
			args: args{
				token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwNDAwMDMxMjUsIlVzZXJJRCI6Mn0.9AF1Z0M2bZpbPSN80pDKLNoDm7RdIseKRDc2Nbi1XWE`,
				uid:   `10`,
			},
			want: want{
				out: &pb.CheckServiceResponse{
					Answer: pb.Answer_Ok,
					Up:     true,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			ctx := context.WithValue(context.Background(), cjwt.UserNum(`UserID`), tt.args.uid)

			if tt.name == `success` {
				minioMock := miniomock.NewMinioStorage(t)
				pgMock := pgmock.NewPGStorage(t)

				minioMock.On(`Ping`, ctx).Return(true)
				pgMock.On(`Ping`, ctx).Return(true)

				s.DB = pgMock
				s.Minio = minioMock
			}

			resp, err := s.CheckService(ctx, &pb.CheckServiceRequest{})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_SaveUserCard(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.SaveUserCardRequest
		sessKey      []byte
		encMasterKey []byte
	}
	type want struct {
		out *pb.SaveUserCardResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
			},
			want: want{
				out: &pb.SaveUserCardResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`SaveUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.SaveUserCard(tt.args.ctx, &pb.SaveUserCardRequest{
				Card: &pb.Card{
					CardNumber: `1234 5678 91011 1213`,
					Cvv:        123,
					Cardholder: `instant issue`,
					Expired: &pb.Expired{
						Month: `01`,
						Year:  `20`,
					},
				},
			})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_GetUserCards(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.GetUserCardsRequest
		sessKey      []byte
		encMasterKey []byte
		encData      []byte
	}
	type want struct {
		out *pb.GetUserCardsResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{27, 143, 125, 164, 36, 0, 201, 65, 224, 91, 73, 208, 188, 245, 173, 248, 93, 255,
					101, 117, 91, 34, 89, 154, 44, 16, 220, 10, 44, 142, 143, 180, 70, 236, 99, 216, 134, 202, 255,
					242, 245, 96, 195, 76, 66, 112, 220, 207, 38, 227, 82, 228},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `2`),
				encData: []byte{1, 228, 224, 109, 26, 24, 124, 74, 189, 175, 215, 53, 13, 148, 163, 76, 154, 122, 117,
					42, 119, 84, 21, 8, 27, 162, 210, 132, 72, 31, 2, 158, 159, 15, 1, 136, 41, 17, 76, 224, 77, 148,
					123, 113, 254, 163, 249, 109, 241, 68, 117, 64, 104, 216, 157, 90, 202, 146, 17, 211, 35, 105, 13,
					139, 29, 187, 67, 186, 132, 1, 201, 74, 236, 199, 215, 43, 142, 217, 116, 87, 214, 69, 222, 183,
					229, 168, 122, 98, 1, 178, 177, 42, 27, 81, 25, 80, 49, 248, 10, 89, 124, 24, 4, 155, 18, 75, 193,
					97, 126, 136, 104, 181, 29, 221, 138, 174, 173, 130, 126, 41, 172, 144, 235, 215, 69, 244, 128,
					134, 130, 81, 87, 180, 77, 122, 199, 148, 119, 153, 183, 75, 64, 182},
			},
			want: want{
				out: &pb.GetUserCardsResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "not found",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx:     context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
				encData: nil,
			},
			want: want{
				out: &pb.GetUserCardsResponse{
					Answer: pb.Answer_NotFound,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			var dataSlice [][]byte

			if tt.args.encData != nil {
				dataSlice = append(dataSlice, tt.args.encData)
			} else {
				dataSlice = nil
			}

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`GetUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(dataSlice, nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.GetUserCards(tt.args.ctx, &pb.GetUserCardsRequest{})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_SaveUserCredentials(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.SaveUserCardRequest
		sessKey      []byte
		encMasterKey []byte
	}
	type want struct {
		out *pb.SaveUserCredentialsResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
			},
			want: want{
				out: &pb.SaveUserCredentialsResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`SaveUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.SaveUserCredentials(tt.args.ctx, &pb.SaveUserCredentialsRequest{
				Credentials: &pb.Credentials{
					Login:    `login`,
					Password: `password`,
				},
			})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_GetUserCredentials(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.GetUserCredentialsRequest
		sessKey      []byte
		encMasterKey []byte
		encData      []byte
	}
	type want struct {
		out *pb.GetUserCredentialsResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{27, 143, 125, 164, 36, 0, 201, 65, 224, 91, 73, 208, 188, 245, 173, 248, 93, 255,
					101, 117, 91, 34, 89, 154, 44, 16, 220, 10, 44, 142, 143, 180, 70, 236, 99, 216, 134, 202, 255,
					242, 245, 96, 195, 76, 66, 112, 220, 207, 38, 227, 82, 228},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `2`),
				encData: []byte{1, 228, 224, 109, 26, 24, 124, 74, 189, 175, 215, 53, 13, 148, 163, 76, 154, 122, 117,
					42, 119, 84, 21, 8, 27, 162, 210, 132, 72, 31, 2, 158, 159, 15, 1, 136, 41, 17, 76, 224, 77, 148,
					123, 113, 254, 163, 249, 109, 241, 68, 117, 64, 104, 216, 157, 90, 202, 146, 17, 211, 35, 105, 13,
					139, 29, 187, 67, 186, 132, 1, 201, 74, 236, 199, 215, 43, 142, 217, 116, 87, 214, 69, 222, 183,
					229, 168, 122, 98, 1, 178, 177, 42, 27, 81, 25, 80, 49, 248, 10, 89, 124, 24, 4, 155, 18, 75, 193,
					97, 126, 136, 104, 181, 29, 221, 138, 174, 173, 130, 126, 41, 172, 144, 235, 215, 69, 244, 128,
					134, 130, 81, 87, 180, 77, 122, 199, 148, 119, 153, 183, 75, 64, 182},
			},
			want: want{
				out: &pb.GetUserCredentialsResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "not found",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx:     context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
				encData: nil,
			},
			want: want{
				out: &pb.GetUserCredentialsResponse{
					Answer: pb.Answer_NotFound,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			var dataSlice [][]byte

			if tt.args.encData != nil {
				dataSlice = append(dataSlice, tt.args.encData)
			} else {
				dataSlice = nil
			}

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`GetUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(dataSlice, nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.GetUserCredentials(tt.args.ctx, &pb.GetUserCredentialsRequest{})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_SaveUserPlain(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.SaveUserCardRequest
		sessKey      []byte
		encMasterKey []byte
	}
	type want struct {
		out *pb.SaveUserPlainResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
			},
			want: want{
				out: &pb.SaveUserPlainResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`SaveUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.SaveUserPlain(tt.args.ctx, &pb.SaveUserPlainRequest{
				Plain: &pb.Plain{
					Title:    `title`,
					BodyText: `text`,
				},
			})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_GetUserPlains(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.GetUserPlainsRequest
		sessKey      []byte
		encMasterKey []byte
		encData      []byte
	}
	type want struct {
		out *pb.GetUserPlainResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{27, 143, 125, 164, 36, 0, 201, 65, 224, 91, 73, 208, 188, 245, 173, 248, 93, 255,
					101, 117, 91, 34, 89, 154, 44, 16, 220, 10, 44, 142, 143, 180, 70, 236, 99, 216, 134, 202, 255,
					242, 245, 96, 195, 76, 66, 112, 220, 207, 38, 227, 82, 228},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `2`),
				encData: []byte{1, 228, 224, 109, 26, 24, 124, 74, 189, 175, 215, 53, 13, 148, 163, 76, 154, 122, 117,
					42, 119, 84, 21, 8, 27, 162, 210, 132, 72, 31, 2, 158, 159, 15, 1, 136, 41, 17, 76, 224, 77, 148,
					123, 113, 254, 163, 249, 109, 241, 68, 117, 64, 104, 216, 157, 90, 202, 146, 17, 211, 35, 105, 13,
					139, 29, 187, 67, 186, 132, 1, 201, 74, 236, 199, 215, 43, 142, 217, 116, 87, 214, 69, 222, 183,
					229, 168, 122, 98, 1, 178, 177, 42, 27, 81, 25, 80, 49, 248, 10, 89, 124, 24, 4, 155, 18, 75, 193,
					97, 126, 136, 104, 181, 29, 221, 138, 174, 173, 130, 126, 41, 172, 144, 235, 215, 69, 244, 128,
					134, 130, 81, 87, 180, 77, 122, 199, 148, 119, 153, 183, 75, 64, 182},
			},
			want: want{
				out: &pb.GetUserPlainResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "not found",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx:     context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
				encData: nil,
			},
			want: want{
				out: &pb.GetUserPlainResponse{
					Answer: pb.Answer_NotFound,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)

			var dataSlice [][]byte

			if tt.args.encData != nil {
				dataSlice = append(dataSlice, tt.args.encData)
			} else {
				dataSlice = nil
			}

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			pgMock.On(`GetUserData`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(dataSlice, nil)

			s.DB = pgMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.GetUserPlains(tt.args.ctx, &pb.GetUserPlainsRequest{})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_SaveUserBinary(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.SaveUserCardRequest
		sessKey      []byte
		encMasterKey []byte
	}
	type want struct {
		out *pb.SaveUserBinaryResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
			},
			want: want{
				out: &pb.SaveUserBinaryResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)
			minioMock := miniomock.NewMinioStorage(t)

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			minioMock.On(`PutObject`, tt.args.ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			s.DB = pgMock
			s.Minio = minioMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.SaveUserBinary(tt.args.ctx, &pb.SaveUserBinaryRequest{
				Name:   `name`,
				Binary: []byte(`body`),
			})

			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_GetUserBinaryList(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.GetUserBinaryListRequest
		sessKey      []byte
		encMasterKey []byte
		list         []string
	}
	type want struct {
		out *pb.GetUserBinaryListResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{27, 143, 125, 164, 36, 0, 201, 65, 224, 91, 73, 208, 188, 245, 173, 248, 93, 255,
					101, 117, 91, 34, 89, 154, 44, 16, 220, 10, 44, 142, 143, 180, 70, 236, 99, 216, 134, 202, 255,
					242, 245, 96, 195, 76, 66, 112, 220, 207, 38, 227, 82, 228},
				ctx:  context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `2`),
				list: []string{`first.php`, `second.php`, `third.php`},
			},
			want: want{
				out: &pb.GetUserBinaryListResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
		{
			name: "not found",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{191, 110, 117, 42, 75, 4, 35, 24, 127, 224, 102, 142, 164, 229, 159, 149, 157,
					48, 65, 3, 24, 8, 2, 199, 226, 35, 95, 65, 85, 43, 113, 68, 66, 163, 44, 48, 118, 87, 211, 206,
					242, 221, 254, 76, 234, 251, 214, 146, 78, 168, 202, 57},
				ctx:  context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `10`),
				list: nil,
			},
			want: want{
				out: &pb.GetUserBinaryListResponse{
					Answer: pb.Answer_NotFound,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			minioMock := miniomock.NewMinioStorage(t)

			minioMock.On(`ListObjects`, tt.args.ctx, mock.Anything).Return(tt.args.list, nil)

			s.Minio = minioMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.GetUserBinaryList(tt.args.ctx, &pb.GetUserBinaryListRequest{})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}

func TestSecureStorageServer_GetUserBinary(t *testing.T) {
	type args struct {
		ctx          context.Context
		in           *pb.GetUserBinaryRequest
		sessKey      []byte
		encMasterKey []byte
		encData      []byte
	}
	type want struct {
		out *pb.GetUserBinaryResponse
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "success",
			args: args{
				sessKey: []byte(`uOlGpExWPfZRQcNJqNOvQSgKGvgysOlH`),
				encMasterKey: []byte{27, 143, 125, 164, 36, 0, 201, 65, 224, 91, 73, 208, 188, 245, 173, 248, 93, 255,
					101, 117, 91, 34, 89, 154, 44, 16, 220, 10, 44, 142, 143, 180, 70, 236, 99, 216, 134, 202, 255,
					242, 245, 96, 195, 76, 66, 112, 220, 207, 38, 227, 82, 228},
				ctx: context.WithValue(context.Background(), cjwt.UserNum(`UserID`), `2`),
				encData: []byte{70, 72, 33, 107, 46, 163, 157, 94, 58, 226, 121, 105, 155, 116, 203, 55, 203, 235, 43,
					150, 195, 132, 146, 31, 121, 59, 98, 104, 117, 97, 178, 199, 1, 192},
			},
			want: want{
				out: &pb.GetUserBinaryResponse{
					Answer: pb.Answer_Ok,
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(SecureStorageServer)
			s.Config.ConfigFile = `../cmd/server/server.json`
			err := s.Init(context.Background())
			require.NoError(t, err)

			pgMock := pgmock.NewPGStorage(t)
			minioMock := miniomock.NewMinioStorage(t)

			pgMock.On(`GetUserKeyByLogin`, tt.args.ctx, mock.Anything).Return(tt.args.sessKey, nil)
			minioMock.On(`GetObject`, tt.args.ctx, mock.Anything, mock.Anything).Return(tt.args.encData, nil)

			s.DB = pgMock
			s.Minio = minioMock
			s.EncryptedMasterKey = tt.args.encMasterKey

			resp, err := s.GetUserBinary(tt.args.ctx, &pb.GetUserBinaryRequest{
				Name: `some`,
			})
			require.Equal(t, tt.want.err, err)
			require.Equal(t, tt.want.out.Answer, resp.Answer)
		})
	}
}
