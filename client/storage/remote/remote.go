package remote

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/MaximMNsk/go-secure-storage/proto"
)

type Storage interface {
	Init() error
	Ping(ctx context.Context) bool
	RegisterUser(ctx context.Context, name, surname, login, password string) (string, error)
	Login(ctx context.Context, login, password string) (string, error)
	GetCards(ctx context.Context, token string) ([]*pb.Card, error)
	AddCard(ctx context.Context, cardNum, cardHolder string, cvv int, expMonth, expYear, token string) error
	GetCredentials(ctx context.Context, token string) ([]*pb.Credentials, error)
	AddCredentials(ctx context.Context, sourceName, login, pwd, token string) error
	GetPlains(ctx context.Context, token string) ([]*pb.Plain, error)
	AddPlain(ctx context.Context, title, body, token string) error
	GetFileList(ctx context.Context, token string) ([]string, error)
	DownloadFile(ctx context.Context, token, fileName string) error
	AddFile(ctx context.Context, token, filePathName string) error
}

type Remote struct {
	client     pb.SecureStorageClient
	remoteHost string
}

func (r *Remote) Init() error {
	if flag.Lookup(`key1`) == nil {
		flag.StringVar(&r.remoteHost, "h", "localhost:8000", "remote host address")
	}
	flag.Parse()

	creds, err := credentials.NewClientTLSFromFile(`./cert/ca.crt`, r.remoteHost)
	if err != nil {
		return err
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(100*1024*1024)))

	conn, err := grpc.NewClient(r.remoteHost, opts...)
	if err != nil {
		return err
	}

	r.client = pb.NewSecureStorageClient(conn)

	return nil
}

func (r *Remote) Ping(ctx context.Context) bool {
	service, err := r.client.CheckService(ctx, &pb.CheckServiceRequest{})
	if err != nil {
		fmt.Println(err)
		return false
	}

	if !service.GetUp() {
		return false
	}

	return true
}

func (r *Remote) RegisterUser(ctx context.Context, name, surname, login, password string) (string, error) {
	req := &pb.RegisterUserRequest{
		Login:    login,
		Password: password,
		User: &pb.User{
			Name:       name,
			SecondName: surname,
		},
	}
	resp, err := r.client.RegisterUser(ctx, req)
	if err != nil {
		return "", err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.GetToken(), nil
	case 1:
		return ``, errors.New(`user already exists`)
	case 6:
		return ``, errors.New(`check your input data`)
	}
	return "", fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) Login(ctx context.Context, login, password string) (string, error) {
	req := &pb.AuthUserRequest{
		Login:    login,
		Password: password,
	}

	resp, err := r.client.AuthUser(ctx, req)
	if err != nil {
		return "", err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.Token, nil
	case 2, 3:
		return resp.Token, errors.New(`incorrect login or password`)
	}
	return "", fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) GetCards(ctx context.Context, token string) ([]*pb.Card, error) {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.GetUserCards(newCtx, &pb.GetUserCardsRequest{})
	if err != nil {
		return nil, err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.GetCards(), nil
	case 4:
		return nil, fmt.Errorf("unauthorized action")
	case 5:
		return nil, fmt.Errorf("not found")
	}
	return nil, fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) AddCard(ctx context.Context, cardNum, cardHolder string, cvv int, expMonth, expYear, token string) error {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	card := &pb.Card{
		CardNumber: cardNum,
		Cardholder: cardHolder,
		Cvv:        int32(cvv),
		Expired: &pb.Expired{
			Year:  expYear,
			Month: expMonth,
		},
	}
	resp, err := r.client.SaveUserCard(newCtx, &pb.SaveUserCardRequest{Card: card})
	if err != nil {
		return err
	}
	switch resp.GetAnswer() {
	case 0:
		return nil
	case 4:
		return errors.New(`unauthorized operation`)
	case 6:
		return errors.New(`inconsistent data`)
	}
	return fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) GetCredentials(ctx context.Context, token string) ([]*pb.Credentials, error) {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.GetUserCredentials(newCtx, &pb.GetUserCredentialsRequest{})
	if err != nil {
		return nil, err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.GetCredentials(), nil
	case 4:
		return nil, fmt.Errorf("unauthorized action")
	case 5:
		return nil, fmt.Errorf("not found")
	}
	return nil, fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) AddCredentials(ctx context.Context, sourceName, login, pwd, token string) error {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.SaveUserCredentials(newCtx, &pb.SaveUserCredentialsRequest{
		Credentials: &pb.Credentials{
			Source:   sourceName,
			Login:    login,
			Password: pwd,
		},
	})
	if err != nil {
		return err
	}
	switch resp.GetAnswer() {
	case 0:
		return nil
	case 4:
		return errors.New(`unauthorized operation`)
	case 6:
		return errors.New(`inconsistent data`)
	}
	return fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) GetPlains(ctx context.Context, token string) ([]*pb.Plain, error) {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.GetUserPlains(newCtx, &pb.GetUserPlainsRequest{})
	if err != nil {
		return nil, err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.GetPlains(), nil
	case 4:
		return nil, fmt.Errorf("unauthorized action")
	case 5:
		return nil, fmt.Errorf("not found")
	}
	return nil, fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) AddPlain(ctx context.Context, title, body, token string) error {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.SaveUserPlain(newCtx, &pb.SaveUserPlainRequest{
		Plain: &pb.Plain{
			Title:    title,
			BodyText: body,
		},
	})
	if err != nil {
		return err
	}
	switch resp.GetAnswer() {
	case 0:
		return nil
	case 4:
		return errors.New(`unauthorized operation`)
	case 6:
		return errors.New(`inconsistent data`)
	}
	return fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) GetFileList(ctx context.Context, token string) ([]string, error) {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.GetUserBinaryList(newCtx, &pb.GetUserBinaryListRequest{})
	if err != nil {
		return nil, err
	}
	switch resp.GetAnswer() {
	case 0:
		return resp.GetNames(), nil
	case 4:
		return nil, fmt.Errorf("unauthorized action")
	case 5:
		return nil, fmt.Errorf("not found")
	}
	return nil, fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}

func (r *Remote) DownloadFile(ctx context.Context, token, fileName string) error {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	resp, err := r.client.GetUserBinary(newCtx, &pb.GetUserBinaryRequest{
		Name: fileName,
	})
	if err != nil {
		return err
	}
	switch resp.GetAnswer() {
	case 0:
		file, err := os.Create(fileName)
		if err != nil {
			return err
		}
		_, err = file.Write(resp.GetBinary())
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	case 4:
		return fmt.Errorf("unauthorized action")
	case 5:
		return fmt.Errorf("not found")
	}
	return nil
}

func (r *Remote) AddFile(ctx context.Context, filePathName, token string) error {
	newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	if len(filePathName) == 0 {
		return fmt.Errorf("invalid file path name")
	}
	fileName := filepath.Base(filePathName)
	if len(fileName) == 0 {
		return fmt.Errorf("invalid file name")
	}

	fileStat, err := os.Stat(filePathName)
	if err != nil {
		return err
	}

	//if fileStat.Size() >= 5*1024*1024 {
	//	return fmt.Errorf("file too large")
	//}

	file, err := os.Open(filePathName)
	if err != nil {
		return err
	}
	defer file.Close() //nolint

	data := make([]byte, fileStat.Size())
	for {
		_, err = file.Read(data)
		if err == io.EOF {
			break
		}
	}

	resp, err := r.client.SaveUserBinary(newCtx, &pb.SaveUserBinaryRequest{
		Name:   fileName,
		Binary: data,
	})
	if err != nil {
		return err
	}
	switch resp.GetAnswer() {
	case 0:
		return nil
	case 4:
		return errors.New(`unauthorized operation`)
	case 6:
		return errors.New(`inconsistent data`)
	}
	return fmt.Errorf("invalid server response: %d", resp.GetAnswer())
}
