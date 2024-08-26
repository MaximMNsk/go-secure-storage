package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	DB                 postgres.PGStorage
	Minio              minio.MinioStorage
	Memory             memory.Storage
	Logger             zerolog.Logger
	MasterUserID       int
	EncryptedMasterKey []byte
	ServerContext      context.Context
	ShutdownProcess    bool
}

const (
	errFailedGetMaster        = "failed to get master user"
	errFailedGetMasterKey     = "failed to get master key"
	errFailedSaveSessionKey   = "failed to save session key"
	errFailedGetSessionKey    = "failed to get session key"
	errFailedEncryptMasterKey = "failed to encrypt master key"
	errFailedDecryptMasterKey = "failed to decrypt master key"
	errFailedStartServer      = "failed to start server"
	errFailedStopServer       = "failed to stop server"
	errUnexpected             = "unexpected error"
	errIncorrectMasterKey     = "incorrect master key"
	errIncorrectUserKey       = "incorrect user key"
	errAlreadyExists          = "already exists"
	errUserNotFound           = "user not found"
	errFailedGetPwd           = "failed to get password"
	errIncorrectPwd           = "incorrect password"
	errUnauthorizedUser       = "unauthorized user"
	errNoCards                = "no cards found"
	errFailedMarshal          = "failed to marshal"
	errFailedUnmarshal        = "failed to unmarshal"
	errFailedConvert          = "failed to convert"
	errFailedGetUserData      = "failed to get user data"
	errFailedEncryptData      = "failed to encrypt data"
	errNotFound               = "not found"
)

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

	s.DB = new(postgres.Storage)
	err = s.DB.Init(ctx, s.Config)
	if err != nil {
		return err
	}
	s.Minio = new(minio.Storage)
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
		grpc.UnaryInterceptor(cjwt.JWTInterceptor),
		grpc.Creds(tlsCredentials),
	)
	return nil
}

func (s *SecureStorageServer) Start() error {
	var err error
	s.MasterUserID, _, _, err = s.DB.GetUserByLogin(s.ServerContext, `MASTER`)
	if err != nil {
		return errors.New(errFailedGetMaster)
	}
	sessionKey := rand.GetString(32)
	err = s.DB.SetUserKey(s.ServerContext, s.MasterUserID, []byte(sessionKey))
	if err != nil {
		return errors.New(errFailedSaveSessionKey)
	}

	if len(s.Config.Keys.Pair1) == 0 || len(s.Config.Keys.Pair2) == 0 {
		s.Config.Keys.Pair1 = s.Config.Keys.Default.Pair1
		s.Config.Keys.Pair2 = s.Config.Keys.Default.Pair2
	}

	masterKey, err := ccrypt.GlueKeys([]byte(s.Config.Keys.Pair1), []byte(s.Config.Keys.Pair2))
	if err != nil {
		return errors.New(errFailedGetMasterKey)
	}
	s.EncryptedMasterKey, err = ccrypt.Encrypt([]byte(sessionKey), masterKey)
	if err != nil {
		return errors.New(errFailedEncryptMasterKey)
	}

	// clear open key for safety
	masterKey = nil //nolint

	listener, err := net.Listen("tcp", s.Config.AppAddr)
	if err != nil {
		return errors.New(errFailedStartServer)
	}
	pb.RegisterSecureStorageServer(s.GRPC, s)
	if err := s.GRPC.Serve(listener); err != nil {
		return errors.New(errFailedStartServer)
	}
	return nil
}

func (s *SecureStorageServer) Stop() error {
	s.ShutdownProcess = true
	err := s.DB.DisableUserKeys(s.ServerContext, s.MasterUserID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(``)
		return errors.New(errFailedStopServer)
	}
	err = s.DB.Destroy()
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(``)
		return err
	}
	err = s.Minio.Destroy()
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(``)
		return err
	}
	err = s.Memory.Destroy()
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(``)
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
		s.Logger.Error().Stack().Err(err).Msg(`failed to hash password 16`)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}
	pwdHash32, err := ccrypt.GetHash(in.GetPassword(), 32)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(`failed to hash password 32`)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(s.ServerContext, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errIncorrectMasterKey)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}
	userKey, err := ccrypt.Encrypt([]byte(pwdHash32), masterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errIncorrectUserKey)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
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
		s.Logger.Error().Stack().Err(err).Msg(errUnexpected)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}

	if duplicate {
		return &pb.RegisterUserResponse{
			Answer: pb.Answer_AlreadyExists,
		}, nil
	}

	jwt, err := cjwt.BuildJWTString(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errUnexpected)
		return &pb.RegisterUserResponse{}, errors.New(errUnexpected)
	}

	return &pb.RegisterUserResponse{
		Token:  jwt,
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) AuthUser(ctx context.Context, in *pb.AuthUserRequest) (*pb.AuthUserResponse, error) {
	if s.ShutdownProcess {
		return &pb.AuthUserResponse{}, nil
	}

	id, _, pwdHash16Stored, err := s.DB.GetUserByLogin(ctx, in.GetLogin())
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errUserNotFound)
		return &pb.AuthUserResponse{
			Answer: pb.Answer_NotFound,
		}, nil
	}

	pwdHash16, err := ccrypt.GetHash(in.GetPassword(), 16)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetPwd)
		return &pb.AuthUserResponse{}, errors.New(errUnexpected)
	}

	if pwdHash16 != pwdHash16Stored {
		s.Logger.Error().Stack().Err(err).Msg(errIncorrectPwd)
		return &pb.AuthUserResponse{
			Answer: pb.Answer_IncorrectPwd,
		}, nil
	}

	token, err := cjwt.BuildJWTString(id)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errUnexpected)
		return &pb.AuthUserResponse{}, errors.New(errUnexpected)
	}

	return &pb.AuthUserResponse{
		Token:  token,
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) CheckService(ctx context.Context, _ *pb.CheckServiceRequest) (*pb.CheckServiceResponse, error) {
	if s.ShutdownProcess {
		return &pb.CheckServiceResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.CheckServiceResponse{}, errors.New(errUnexpected)
	}

	if UID < 1 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.CheckServiceResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	health := s.DB.Ping(ctx) && s.Minio.Ping(ctx)
	return &pb.CheckServiceResponse{
		Up:     health,
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) SaveUserCard(ctx context.Context, in *pb.SaveUserCardRequest) (*pb.SaveUserCardResponse, error) {
	if s.ShutdownProcess {
		return &pb.SaveUserCardResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.SaveUserCardResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}

	card := in.GetCard()
	card.Expired = in.GetCard().GetExpired()

	cardData, err := json.Marshal(card)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(`failed to marshal card`)
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}

	encryptedCardData, err := ccrypt.Encrypt(masterKey, cardData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(`failed to encrypt card data`)
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}

	err = s.DB.SaveUserData(ctx, UID, `card`, encryptedCardData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(string(cardData))
		return &pb.SaveUserCardResponse{}, errors.New(errUnexpected)
	}

	return &pb.SaveUserCardResponse{
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) GetUserCards(ctx context.Context, _ *pb.GetUserCardsRequest) (*pb.GetUserCardsResponse, error) {
	if s.ShutdownProcess {
		return &pb.GetUserCardsResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.GetUserCardsResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
	}

	cards := make([]*pb.Card, 0)

	// get slice of encrypted cards
	data, err := s.DB.GetUserData(ctx, UID, `card`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetUserData)
		return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
	}

	if len(data) == 0 {
		s.Logger.Warn().Stack().Msg(errNoCards)
		return &pb.GetUserCardsResponse{
			Answer: pb.Answer_NotFound,
		}, nil
	}

	for _, v := range data {
		decodedCardData, err := ccrypt.Decrypt(masterKey, v)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(string(v))
			return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
		}

		var card *pb.Card

		err = json.Unmarshal(decodedCardData, &card)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(errFailedUnmarshal)
			return &pb.GetUserCardsResponse{}, errors.New(errUnexpected)
		}
		cards = append(cards, card)
	}

	return &pb.GetUserCardsResponse{
		Cards:  cards,
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) SaveUserCredentials(ctx context.Context, in *pb.SaveUserCredentialsRequest) (*pb.SaveUserCredentialsResponse, error) {
	if s.ShutdownProcess {
		return &pb.SaveUserCredentialsResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.SaveUserCredentialsResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	creds := in.GetCredentials()

	credsData, err := json.Marshal(creds)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedMarshal)
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	encryptedCredsData, err := ccrypt.Encrypt(masterKey, credsData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedEncryptData)
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	err = s.DB.SaveUserData(ctx, UID, `credentials`, encryptedCredsData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(string(credsData))
		return &pb.SaveUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	return &pb.SaveUserCredentialsResponse{
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) GetUserCredentials(ctx context.Context, _ *pb.GetUserCredentialsRequest) (*pb.GetUserCredentialsResponse, error) {
	if s.ShutdownProcess {
		return &pb.GetUserCredentialsResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.GetUserCredentialsResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	creds := make([]*pb.Credentials, 0)

	data, err := s.DB.GetUserData(ctx, UID, `credentials`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetUserData)
		return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
	}

	if len(data) == 0 {
		return &pb.GetUserCredentialsResponse{
			Answer: pb.Answer_NotFound,
		}, nil
	}

	for _, v := range data {
		decodedCardData, err := ccrypt.Decrypt(masterKey, v)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(string(v))
			return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
		}

		var cred *pb.Credentials

		err = json.Unmarshal(decodedCardData, &cred)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(errFailedUnmarshal)
			return &pb.GetUserCredentialsResponse{}, errors.New(errUnexpected)
		}
		creds = append(creds, cred)
	}

	return &pb.GetUserCredentialsResponse{
		Credentials: creds,
		Answer:      pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) SaveUserPlain(ctx context.Context, in *pb.SaveUserPlainRequest) (*pb.SaveUserPlainResponse, error) {
	if s.ShutdownProcess {
		return &pb.SaveUserPlainResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.SaveUserPlainResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}

	plain := in.GetPlain()

	plainData, err := json.Marshal(plain)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedMarshal)
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}

	encryptedPlainData, err := ccrypt.Encrypt(masterKey, plainData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedEncryptData)
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}

	err = s.DB.SaveUserData(ctx, UID, `plain`, encryptedPlainData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(string(plainData))
		return &pb.SaveUserPlainResponse{}, errors.New(errUnexpected)
	}

	return &pb.SaveUserPlainResponse{
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) GetUserPlains(ctx context.Context, _ *pb.GetUserPlainsRequest) (*pb.GetUserPlainResponse, error) {
	if s.ShutdownProcess {
		return &pb.GetUserPlainResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.GetUserPlainResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
	}

	plains := make([]*pb.Plain, 0)

	data, err := s.DB.GetUserData(ctx, UID, `plain`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetUserData)
		return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
	}

	if len(data) == 0 {
		return &pb.GetUserPlainResponse{
			Answer: pb.Answer_NotFound,
		}, nil
	}

	for _, v := range data {
		decodedCardData, err := ccrypt.Decrypt(masterKey, v)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(string(v))
			return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
		}

		var plain *pb.Plain

		err = json.Unmarshal(decodedCardData, &plain)
		if err != nil {
			s.Logger.Error().Stack().Err(err).Msg(errFailedUnmarshal)
			return &pb.GetUserPlainResponse{}, errors.New(errUnexpected)
		}
		plains = append(plains, plain)
	}

	return &pb.GetUserPlainResponse{
		Plains: plains,
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) SaveUserBinary(ctx context.Context, in *pb.SaveUserBinaryRequest) (*pb.SaveUserBinaryResponse, error) {
	if s.ShutdownProcess {
		return &pb.SaveUserBinaryResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.SaveUserBinaryResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.SaveUserBinaryResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.SaveUserBinaryResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.SaveUserBinaryResponse{}, errors.New(errUnexpected)
	}

	binary := in.GetBinary()

	encryptedBinaryData, err := ccrypt.Encrypt(masterKey, binary)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedEncryptData)
		return &pb.SaveUserBinaryResponse{}, errors.New(errUnexpected)
	}

	err = s.Minio.PutObject(ctx, userID, in.GetName(), encryptedBinaryData)
	if err != nil {
		if strings.Contains(err.Error(), errAlreadyExists) {
			return &pb.SaveUserBinaryResponse{
				Answer: pb.Answer_AlreadyExists,
			}, nil
		}
		s.Logger.Error().Stack().Err(err).Msg(string(binary))
		return &pb.SaveUserBinaryResponse{}, errors.New(errUnexpected)
	}

	return &pb.SaveUserBinaryResponse{
		Answer: pb.Answer_Ok,
	}, nil
}

func (s *SecureStorageServer) GetUserBinaryList(ctx context.Context, _ *pb.GetUserBinaryListRequest) (*pb.GetUserBinaryListResponse, error) {
	if s.ShutdownProcess {
		return &pb.GetUserBinaryListResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.GetUserBinaryListResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.GetUserBinaryListResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	objects, err := s.Minio.ListObjects(ctx, userID)
	if err != nil {
		return nil, err
	}

	if len(objects) == 0 {
		s.Logger.Warn().Stack().Msg(errNotFound)
		return &pb.GetUserBinaryListResponse{
			Answer: pb.Answer_NotFound,
			Names:  nil,
		}, nil
	}

	return &pb.GetUserBinaryListResponse{
		Answer: pb.Answer_Ok,
		Names:  objects,
	}, nil
}

func (s *SecureStorageServer) GetUserBinary(ctx context.Context, in *pb.GetUserBinaryRequest) (*pb.GetUserBinaryResponse, error) {
	if s.ShutdownProcess {
		return &pb.GetUserBinaryResponse{}, nil
	}

	userID := ctx.Value(cjwt.UserNum(`UserID`)).(string)
	UID, err := strconv.Atoi(userID)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedConvert)
		return &pb.GetUserBinaryResponse{}, errors.New(errUnexpected)
	}

	if UID <= 0 {
		s.Logger.Error().Stack().Err(err).Msg(errUnauthorizedUser)
		return &pb.GetUserBinaryResponse{
			Answer: pb.Answer_UnauthorizedUser,
		}, nil
	}

	sessionKey, err := s.DB.GetUserKeyByLogin(ctx, `MASTER`)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedGetSessionKey)
		return &pb.GetUserBinaryResponse{}, errors.New(errUnexpected)
	}
	masterKey, err := ccrypt.Decrypt(sessionKey, s.EncryptedMasterKey)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errFailedDecryptMasterKey)
		return &pb.GetUserBinaryResponse{}, errors.New(errUnexpected)
	}

	binaryData, err := s.Minio.GetObject(ctx, userID, in.GetName())
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errUnexpected)
		return &pb.GetUserBinaryResponse{}, errors.New(errNotFound)
	}

	decodedBinaryData, err := ccrypt.Decrypt(masterKey, binaryData)
	if err != nil {
		s.Logger.Error().Stack().Err(err).Msg(errUnexpected)
		return &pb.GetUserBinaryResponse{}, errors.New(errUnexpected)
	}

	return &pb.GetUserBinaryResponse{
		Name:   in.GetName(),
		Binary: decodedBinaryData,
		Answer: pb.Answer_Ok,
	}, nil
}

func main() {
	ctx := context.Background()
	serv := new(SecureStorageServer)
	err := serv.Init(ctx)
	if err != nil {
		serv.Logger.Error().Stack().Err(err).Msg(errUnexpected)
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
		serv.Logger.Error().Stack().Err(err).Msg(``)
	}
}
