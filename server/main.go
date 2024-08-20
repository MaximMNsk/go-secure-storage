package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/MaximMNsk/go-secure-storage/internal/ccrypt"
	"github.com/MaximMNsk/go-secure-storage/internal/cjwt"
	"github.com/MaximMNsk/go-secure-storage/internal/rand"
	pb "github.com/MaximMNsk/go-secure-storage/proto"
	"github.com/MaximMNsk/go-secure-storage/server/config"
	"github.com/MaximMNsk/go-secure-storage/server/storage/memory"
	"github.com/MaximMNsk/go-secure-storage/server/storage/minio"
	"github.com/MaximMNsk/go-secure-storage/server/storage/postgres"
)

type SecureStorageServer struct {
	pb.UnimplementedSecureStorageServer
	Config             config.Config
	GRPC               *grpc.Server
	DB                 postgres.Storage
	Minio              minio.Storage
	Memory             memory.Storage
	Logger             zerolog.Logger
	MasterUserID       int
	EncryptedMasterKey []byte
	ServerContext      context.Context
	ShutdownProcess    bool
}

func (s *SecureStorageServer) Init(ctx context.Context) error {
	s.ShutdownProcess = false
	s.ServerContext = ctx

	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	s.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	err := s.Config.Init()
	if err != nil {
		return err
	}

	err = s.DB.Init(ctx, s.Config)
	if err != nil {
		return err
	}
	err = s.Minio.Init(ctx, s.Config)
	if err != nil {
		return err
	}
	err = s.Memory.Init(ctx, s.Config)
	if err != nil {
		return err
	}

	serverCert, err := tls.LoadX509KeyPair(s.Config.Tlc.PublicPath, s.Config.Tlc.PrivatePath)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}
	tlsCredentials := credentials.NewTLS(tlsCfg)

	s.GRPC = grpc.NewServer(
		grpc.Creds(tlsCredentials),
		//grpc.UnaryInterceptor(mtd.JWTInterceptor),
	)
	return nil
}

func (s *SecureStorageServer) Start() error {
	var err error
	s.MasterUserID, _, _, err = s.DB.GetUserByLogin(s.ServerContext, `MASTER`)
	if err != nil {
		return errors.New("failed to get master user")
	}
	sessionKey := rand.GetString(32)
	err = s.DB.SetUserKey(s.ServerContext, s.MasterUserID, []byte(sessionKey))
	if err != nil {
		return errors.New("failed to save session key")
	}

	if len(s.Config.Keys.Pair1) == 0 || len(s.Config.Keys.Pair2) == 0 {
		s.Config.Keys.Pair1 = s.Config.Keys.Default.Pair1
		s.Config.Keys.Pair2 = s.Config.Keys.Default.Pair2
	}

	masterKey, err := ccrypt.GlueKeys([]byte(s.Config.Keys.Pair1), []byte(s.Config.Keys.Pair2))
	if err != nil {
		return errors.New("failed to get master key")
	}
	s.EncryptedMasterKey, err = ccrypt.Encrypt([]byte(sessionKey), masterKey)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return errors.New("failed to encrypt master key")
	}

	// clear open key
	masterKey = []byte(``)

	listener, err := net.Listen("tcp", s.Config.AppAddr)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return errors.New("failed to start server")
	}
	pb.RegisterSecureStorageServer(s.GRPC, s)
	if err := s.GRPC.Serve(listener); err != nil {
		s.Logger.Error().Msg(err.Error())
		return errors.New(`failed to start server`)
	}
	return nil
}

func (s *SecureStorageServer) Stop() error {
	s.ShutdownProcess = true
	err := s.DB.DisableUserKeys(s.ServerContext, s.MasterUserID)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return errors.New("failed to stop server")
	}
	err = s.DB.Destroy()
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return err
	}
	err = s.Minio.Destroy()
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return err
	}
	err = s.Memory.Destroy()
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return err
	}
	s.GRPC.Stop()
	return nil
}

func (s *SecureStorageServer) RegisterUser(ctx context.Context, in *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	if s.ShutdownProcess {
		return &pb.RegisterUserResponse{}, nil
	}

	pwdHash16, err := ccrypt.GetHash(in.GetPassword(), 16)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.RegisterUserResponse{}, errors.New("failed to hash password 16")
	}
	pwdHash32, err := ccrypt.GetHash(in.GetPassword(), 32)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.RegisterUserResponse{}, errors.New(`failed to hash password 32`)
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(s.ServerContext, `MASTER`)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.RegisterUserResponse{}, errors.New(`failed to get session key`)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.RegisterUserResponse{}, errors.New(`incorrect master key`)
	}
	userKey, err := ccrypt.Encrypt([]byte(pwdHash32), masterKey)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.RegisterUserResponse{}, errors.New(`incorrect user key`)
	}

	userID, duplicate, err := s.DB.SaveUser(
		ctx,
		in.GetUser().GetName(),
		in.GetUser().GetSecondName(),
		in.GetLogin(),
		pwdHash16,
		userKey,
	)
	if err != nil && !duplicate {
		s.Logger.Error().Msg(err.Error())
		return nil, errors.New(`unexpected error`)
	}

	if duplicate {
		return nil, errors.New(`user already exists`)
	}

	jwt, err := cjwt.BuildJWTString(userID)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return nil, errors.New(`unexpected error`)
	}

	return &pb.RegisterUserResponse{
		Token:  jwt,
		IsAuth: true,
	}, nil
}

func (s *SecureStorageServer) AuthUser(ctx context.Context, in *pb.AuthUserRequest) (*pb.AuthUserResponse, error) {
	if s.ShutdownProcess {
		return &pb.AuthUserResponse{}, nil
	}

	id, _, pwdHash16Stored, err := s.DB.GetUserByLogin(ctx, in.GetLogin())
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(err.Error())
		return &pb.AuthUserResponse{}, errors.New(`user not found`)
	}

	pwdHash16, err := ccrypt.GetHash(in.GetPassword(), 16)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.AuthUserResponse{}, errors.New(`failed to get password`)
	}

	if pwdHash16 != pwdHash16Stored {
		s.Logger.Error().Msg(`incorrect password`)
		return &pb.AuthUserResponse{}, errors.New(`incorrect password`)
	}

	token, err := cjwt.BuildJWTString(id)
	if err != nil {
		s.Logger.Error().Msg(err.Error())
		return &pb.AuthUserResponse{}, errors.New(`unexpected error`)
	}

	return &pb.AuthUserResponse{
		Token:  token,
		IsAuth: true,
	}, nil
}

func (s *SecureStorageServer) CheckService(ctx context.Context, _ *pb.CheckServiceRequest) (*pb.CheckServiceResponse, error) {
	health := s.DB.Ping(ctx) || s.Minio.Ping(ctx) || s.Memory.Ping(ctx)
	return &pb.CheckServiceResponse{Up: health}, nil
}

func main() {
	ctx := context.Background()
	serv := new(SecureStorageServer)
	err := serv.Init(ctx)
	if err != nil {
		serv.Logger.Error().Msg(err.Error())
		return
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		for {
			select {
			case <-exit:
				serv.Logger.Info().Msg(`stopping server`)
				stopped := serv.Stop()
				if stopped != nil {
					serv.Logger.Error().Err(errors.New(`incorrectly stopping server`))
				}
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	}()

	if len(serv.Config.Keys.Pair1) == 0 || len(serv.Config.Keys.Pair2) == 0 {
		serv.Logger.Warn().Msg(`make sure both key pairs are correct!`)
		serv.Logger.Warn().Msg(`if you do not specify keys (params -key1, -key2), the default keys will be used`)
	}
	serv.Logger.Info().Msg(`starting server`)
	err = serv.Start()
	if err != nil {
		serv.Logger.Error().Msg(err.Error())
	}
}
