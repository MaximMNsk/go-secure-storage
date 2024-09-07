package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/MaximMNsk/go-secure-storage/client/pages"
	"github.com/MaximMNsk/go-secure-storage/client/pages/addcard"
	"github.com/MaximMNsk/go-secure-storage/client/pages/addcredetials"
	"github.com/MaximMNsk/go-secure-storage/client/pages/addfile"
	"github.com/MaximMNsk/go-secure-storage/client/pages/addplain"
	"github.com/MaximMNsk/go-secure-storage/client/pages/login"
	"github.com/MaximMNsk/go-secure-storage/client/pages/primary"
	"github.com/MaximMNsk/go-secure-storage/client/pages/register"
	"github.com/MaximMNsk/go-secure-storage/client/pages/showcards"
	"github.com/MaximMNsk/go-secure-storage/client/pages/showcredentials"
	"github.com/MaximMNsk/go-secure-storage/client/pages/showfiles"
	"github.com/MaximMNsk/go-secure-storage/client/pages/showplains"
	"github.com/MaximMNsk/go-secure-storage/client/storage/remote"
	"github.com/MaximMNsk/go-secure-storage/internal/messages"
)

// env GOOS=windows GOARCH=amd64 go build -ldflags "-X main.buildVersion=1.21 -X 'main.buildDate=$(date +'%Y/%m/%d %H:%M:%S')'" -o win.client.exe main.go
// go build -ldflags "-X main.buildVersion=1.21 -X 'main.buildDate=$(date +'%Y/%m/%d %H:%M:%S')'" -o linux.client main.go
var (
	buildVersion string
	buildDate    string
)

func main() {
	if buildVersion == `` {
		buildVersion = `N/A`
	}
	if buildDate == `` {
		buildDate = `N/A`
	}
	fmt.Println(`Build version:`, buildVersion)
	fmt.Println(`Build date:`, buildDate)

	client := new(Client)
	err := client.init()
	if err != nil {
		client.Logger.Err(err).Stack().Msg(``)
		return
	}

	go client.tokenObserver()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go client.routeObserver(wg)
	wg.Wait()
}

// Client - основная структура клиента.
type Client struct {
	NeedLog      bool
	Logger       zerolog.Logger
	Storage      remote.Storage
	RouteCh      chan messages.Message
	TokenCh      chan messages.Message
	Token        string
	RouteMessage string
}

// init - инициализация клиента с настройками.
func (c *Client) init() error {
	if flag.Lookup(`l`) == nil {
		flag.BoolVar(&c.NeedLog, "l", false, "logfile will be create in the same directory as the client")
	}
	flag.Parse()

	logLevel := zerolog.NoLevel
	var runLogFile *os.File
	if c.NeedLog {
		logLevel = zerolog.TraceLevel
		runLogFile, _ = os.OpenFile(
			"client.log",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664,
		)
	}
	zerolog.SetGlobalLevel(logLevel)
	multi := zerolog.MultiLevelWriter(runLogFile)
	c.Logger = zerolog.New(multi).With().Timestamp().Logger()
	c.Storage = new(remote.Remote)
	err := c.Storage.Init()
	if err != nil {
		return err
	}
	c.RouteCh = make(chan messages.Message)
	c.TokenCh = make(chan messages.Message)
	go func() {
		msg := new(messages.Message)
		c.RouteCh <- msg.GetStartRoute()
	}()

	return nil
}

// routeObserver - роутинг запросов на определенные страницы.
func (c *Client) routeObserver(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select { //nolint
		case route, ok := <-c.RouteCh:
			if ok {
				c.RouteMessage = route.Message
				switch route.Content {
				case messages.RouteStart:
					menu := new(pages.Menu)
					err := menu.Show(c.Storage, c.RouteCh, c.RouteMessage)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteExit:
					close(c.RouteCh)
					c.Logger.Info().Msg("route exited")
					return
				case messages.RouteRegister:
					regPage := new(register.Model)
					err := regPage.Show(c.Storage, c.RouteCh, c.TokenCh)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteLogin:
					loginPage := new(login.Model)
					err := loginPage.Show(c.Storage, c.RouteCh, c.TokenCh)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RoutePrimary:
					primaryPage := new(primary.Menu)
					err := primaryPage.Show(c.Storage, c.RouteCh, c.Token, c.RouteMessage)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteShowCards:
					primaryPage := new(showcards.Model)
					err := primaryPage.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteAddCard:
					primaryPage := new(addcard.Model)
					err := primaryPage.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteShowCredentials:
					showCredentials := new(showcredentials.Model)
					err := showCredentials.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteAddCredentials:
					addCredentials := new(addcredetials.Model)
					err := addCredentials.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteShowPlains:
					showPlains := new(showplains.Model)
					err := showPlains.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteAddPlain:
					addPlain := new(addplain.Model)
					addPlain.Init()
					err := addPlain.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteShowFiles:
					showFiles := new(showfiles.Model)
					err := showFiles.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				case messages.RouteAddFile:
					addFile := new(addfile.Model)
					err := addFile.Show(c.Storage, c.RouteCh, c.Token)
					if err != nil {
						c.Logger.Err(err)
						return
					}
				}
			}
		default:
			time.Sleep(time.Millisecond * 100)
		}
	}
}

// tokenObserver - передача токена.
func (c *Client) tokenObserver() {
	for {
		select { //nolint
		case token, ok := <-c.TokenCh:
			if ok {
				c.Token = token.Content
			}
		default:
			time.Sleep(time.Millisecond * 100)
		}
	}
}
