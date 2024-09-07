package messages

import (
	"strings"
)

const (
	Route = `route`
	Token = `token`

	RouteExit            = `Exit`
	RouteStart           = `Start`
	RouteRegister        = `Register`
	RouteLogin           = `Login`
	RouteLogout          = `Logout`
	RoutePrimary         = `Primary`
	RouteShowCards       = `ShowCards`
	RouteAddCard         = `AddCard`
	RouteShowCredentials = `ShowCredentials`
	RouteAddCredentials  = `AddCredentials`
	RouteShowPlains      = `ShowPlains`
	RouteAddPlain        = `AddPlain`
	RouteShowFiles       = `ShowFiles`
	RouteAddFile         = `AddFile`
)

type Message struct {
	Type    string
	Content string
	Message string
}

func NewMessage(typ string, content string, message string) Message {
	return Message{
		Type:    typ,
		Content: content,
		Message: message,
	}
}

func (m *Message) GetExitRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteExit,
	}
}
func (m *Message) GetStartRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteStart,
	}
}
func (m *Message) GetRegisterRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteRegister,
	}
}
func (m *Message) GetLoginRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteLogin,
	}
}
func (m *Message) GetLogoutRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteLogout,
	}
}
func (m *Message) GetPrimaryRoute() Message {
	return Message{
		Type:    Route,
		Content: RoutePrimary,
	}
}
func (m *Message) GetShowCardsRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteShowCards,
	}
}
func (m *Message) GetAddCardRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteAddCard,
	}
}
func (m *Message) GetShowCredentialsRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteShowCredentials,
	}
}
func (m *Message) GetAddCredentialsRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteAddCredentials,
	}
}
func (m *Message) GetShowPlainsRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteShowPlains,
	}
}
func (m *Message) GetAddPlainRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteAddPlain,
	}
}
func (m *Message) GetShowFilesRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteShowFiles,
	}
}
func (m *Message) GetAddFileRoute() Message {
	return Message{
		Type:    Route,
		Content: RouteAddFile,
	}
}

func PrepareRoute(text string) string {
	if len(text) == 0 {
		return ``
	}
	words := strings.Split(text, " ")
	for i, word := range words {
		words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}

	return strings.Join(words, "")
}
