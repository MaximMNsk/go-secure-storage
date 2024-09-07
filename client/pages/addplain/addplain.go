package addplain

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/MaximMNsk/go-secure-storage/client/storage/remote"
	"github.com/MaximMNsk/go-secure-storage/internal/messages"
)

type (
	errMsg error
)

const (
	hotPink  = lipgloss.Color("#FF06B7")
	darkGray = lipgloss.Color("#767676")
)

var (
	inputStyle    = lipgloss.NewStyle().Foreground(hotPink)
	continueStyle = lipgloss.NewStyle().Foreground(darkGray)
)

type Model struct {
	inputTitle textinput.Model
	inputBody  textarea.Model
	err        error
}

func textValidator(s string) error {
	if len(s) < 5 {
		return fmt.Errorf("text is too short")
	}
	return nil
}

func initialModel() *Model {
	inputTitle := textinput.New()
	inputTitle.Placeholder = " TITLE "
	inputTitle.Focus()
	inputTitle.CharLimit = 20
	inputTitle.Width = 30
	inputTitle.Prompt = ""
	inputTitle.Validate = textValidator

	inputBody := textarea.New()
	inputBody.CharLimit = 512
	inputBody.MaxWidth = 64
	inputBody.MaxHeight = 10
	inputBody.Prompt = ""

	return &Model{
		inputTitle: inputTitle,
		inputBody:  inputBody,
		err:        nil,
	}
}

// Init - инициализация объекта TUI перед запуском.
func (m *Model) Init() tea.Cmd { //nolint
	return textinput.Blink
	//return nil
}

// Update - обработка событий клавиатуры.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds = make([]tea.Cmd, 2)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type { //nolint
		case tea.KeyCtrlHome, tea.KeyHome:
			go func() {
				RouterProxyChan <- new(messages.Message).GetPrimaryRoute()
			}()
			return m, tea.Quit
		case tea.KeyCtrlS:
			var err error
			err = ServerStorage.AddPlain(context.Background(),
				m.inputTitle.Value(),
				m.inputBody.Value(),
				Token)
			if err != nil {
				go func() {
					RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, err.Error())
				}()
			}
			go func() {
				RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, `successfully`)
			}()
			return m, tea.Quit
		case tea.KeyCtrlC, tea.KeyEsc:
			go func() {
				RouterProxyChan <- new(messages.Message).GetExitRoute()
			}()
			return m, tea.Quit
		case tea.KeyTab, tea.KeyCtrlN:
			if m.inputTitle.Focused() {
				m.inputTitle.Blur()
				m.inputBody.Focus()
			} else if m.inputBody.Focused() {
				m.inputBody.Blur()
				m.inputTitle.Focus()
			}
		}

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	m.inputTitle, cmds[0] = m.inputTitle.Update(msg)
	m.inputBody, cmds[1] = m.inputBody.Update(msg)

	return m, tea.Batch(cmds...)
}

// View - определение отображения интерфейса пользователя.
func (m *Model) View() string {
	return fmt.Sprintf(
		` 

 %s
 %s

 %s
 %s

 
 %s
 %s
`,
		inputStyle.Width(30).Render("Title"),
		m.inputTitle.View(),
		inputStyle.Width(35).Render("Text"),
		m.inputBody.View(),
		continueStyle.Render("Press Tab to switch next field"),
		continueStyle.Render("Or press Ctrl+S to save..."),
	) + "\n"
}

var (
	RouterProxyChan chan messages.Message
	ServerStorage   remote.Storage
	Token           string
)

// Show - запуск интерфейса.
func (m *Model) Show(storage remote.Storage, routerCh chan messages.Message, token string) error { //nolint
	RouterProxyChan = routerCh
	ServerStorage = storage
	Token = token

	if len(Token) == 0 {
		RouterProxyChan <- messages.NewMessage(messages.Route, messages.RouteStart, `Unauthorized action`)
		return nil
	}

	if !storage.Ping(context.Background()) {
		RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, `Service unavailable!!!`)
		return nil
	}

	p := tea.NewProgram(initialModel())

	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
