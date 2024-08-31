package addfile

import (
	"context"
	"fmt"

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
	flp = iota
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
	inputs  []textinput.Model
	focused int
	err     error
}

func initialModel() *Model {
	var inputs = make([]textinput.Model, 1)

	inputs[flp] = textinput.New()
	inputs[flp].Placeholder = "full path to the file with filename"
	inputs[flp].CharLimit = 128
	inputs[flp].Width = 50
	inputs[flp].Prompt = ""
	inputs[flp].Focus()

	return &Model{
		inputs:  inputs,
		focused: 0,
		err:     nil,
	}
}

func (m *Model) Init() tea.Cmd { //nolint
	return textinput.Blink
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds = make([]tea.Cmd, len(m.inputs))

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type { //nolint
		case tea.KeyCtrlHome, tea.KeyHome:
			go func() {
				RouterProxyChan <- new(messages.Message).GetPrimaryRoute()
			}()
			return m, tea.Quit
		case tea.KeyCtrlS:
			err := ServerStorage.AddFile(context.Background(),
				m.inputs[flp].Value(),
				Token)
			if err != nil {
				go func() {
					RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, err.Error())
				}()
				return m, tea.Quit
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
		case tea.KeyShiftTab, tea.KeyCtrlP:
			m.prevInput()
		case tea.KeyTab, tea.KeyCtrlN:
			m.nextInput()
		}
		for i := range m.inputs {
			m.inputs[i].Blur()
		}
		m.inputs[m.focused].Focus()

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m *Model) View() string {
	return fmt.Sprintf(
		` 
 

 %s
 %s




 %s
 %s
`,
		inputStyle.Width(50).Render("File (100 MB max)"),
		m.inputs[flp].View(),
		continueStyle.Render("Press Tab to switch next field"),
		continueStyle.Render("Or press Ctrl+S to save..."),
	) + "\n"
}

// nextInput focuses the next input field
func (m *Model) nextInput() {
	m.focused = (m.focused + 1) % len(m.inputs)
}

// prevInput focuses the previous input field
func (m *Model) prevInput() {
	m.focused--
	// Wrap around
	if m.focused < 0 {
		m.focused = len(m.inputs) - 1
	}
}

var (
	RouterProxyChan chan messages.Message
	ServerStorage   remote.Storage
	Token           string
)

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
