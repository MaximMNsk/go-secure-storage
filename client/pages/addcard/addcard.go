package addcard

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
	ccn = iota
	chn
	expm
	expy
	cvv
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

// Validator functions to ensure valid input
func ccnValidator(s string) error {
	// Credit Card Number should a string less than 20 digits
	// It should include 16 integers and 3 spaces
	if len(s) > 16+3 {
		return fmt.Errorf("CCN is too long")
	}

	if len(s) == 0 || len(s)%5 != 0 && (s[len(s)-1] < '0' || s[len(s)-1] > '9') {
		return fmt.Errorf("CCN is invalid")
	}

	// The last digit should be a number unless it is a multiple of 4 in which
	// case it should be a space
	if len(s)%5 == 0 && s[len(s)-1] != ' ' {
		return fmt.Errorf("CCN must separate groups with spaces")
	}

	// The remaining digits should be integers
	c := strings.ReplaceAll(s, " ", "")
	_, err := strconv.ParseInt(c, 10, 64)

	return err
}

func expValidator(s string) error {
	// The 3 character should be a slash (/)
	// The rest should be numbers
	e := strings.ReplaceAll(s, "/", "")
	_, err := strconv.ParseInt(e, 10, 64)
	if err != nil {
		return fmt.Errorf("EXP is invalid")
	}

	// There should be only one slash and it should be in the 2nd index (3rd character)
	if len(s) >= 3 && (strings.Index(s, "/") != 2 || strings.LastIndex(s, "/") != 2) {
		return fmt.Errorf("EXP is invalid")
	}

	return nil
}

func cvvValidator(s string) error {
	// The CVV should be a number of 3 digits
	// Since the input will already ensure that the CVV is a string of length 3,
	// All we need to do is check that it is a number
	_, err := strconv.ParseInt(s, 10, 64)
	return err
}

func chnValidator(s string) error {
	if len(s) < 5 {
		return fmt.Errorf("CHN is too short")
	}
	return nil
}

func initialModel() Model {
	var inputs = make([]textinput.Model, 5)
	inputs[ccn] = textinput.New()
	inputs[ccn].Placeholder = "4505 **** **** 1234"
	inputs[ccn].Focus()
	inputs[ccn].CharLimit = 20
	inputs[ccn].Width = 30
	inputs[ccn].Prompt = ""
	inputs[ccn].Validate = ccnValidator

	inputs[chn] = textinput.New()
	inputs[chn].Placeholder = "INSTANT ISSUE"
	inputs[chn].CharLimit = 64
	inputs[chn].Width = 30
	inputs[chn].Prompt = ""
	inputs[chn].Validate = chnValidator

	inputs[expm] = textinput.New()
	inputs[expm].Placeholder = "MM "
	inputs[expm].CharLimit = 2
	inputs[expm].Width = 5
	inputs[expm].Prompt = ""
	inputs[expm].Validate = expValidator

	inputs[expy] = textinput.New()
	inputs[expy].Placeholder = "YY "
	inputs[expy].CharLimit = 2
	inputs[expy].Width = 5
	inputs[expy].Prompt = ""
	inputs[expy].Validate = expValidator

	inputs[cvv] = textinput.New()
	inputs[cvv].Placeholder = "XXX"
	inputs[cvv].CharLimit = 3
	inputs[cvv].Width = 5
	inputs[cvv].Prompt = ""
	inputs[cvv].Validate = cvvValidator

	return Model{
		inputs:  inputs,
		focused: 0,
		err:     nil,
	}
}

func (m Model) Init() tea.Cmd { //nolint
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds = make([]tea.Cmd, len(m.inputs))

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlHome, tea.KeyHome:
			go func() {
				RouterProxyChan <- new(messages.Message).GetPrimaryRoute()
			}()
			return m, tea.Quit
		case tea.KeyCtrlS:
			fieldCvv, err := strconv.Atoi(m.inputs[cvv].Value())
			if err != nil {
				go func() {
					RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, err.Error())
				}()
				return m, tea.Quit
			}
			err = ServerStorage.AddCard(context.Background(),
				m.inputs[ccn].Value(),
				m.inputs[chn].Value(),
				fieldCvv,
				m.inputs[expm].Value(),
				m.inputs[expy].Value(),
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

func (m Model) View() string {
	return fmt.Sprintf(
		` 

 %s
 %s

 %s
 %s

 %s
 %s  %s

 %s
 %s

 %s
 %s
`,
		inputStyle.Width(30).Render("Card Number"),
		m.inputs[ccn].View(),
		inputStyle.Width(35).Render("Cardholder"),
		m.inputs[chn].View(),
		inputStyle.Width(6).Render("EXP"),
		m.inputs[expm].View(),
		m.inputs[expy].View(),
		inputStyle.Width(6).Render("CVV"),
		m.inputs[cvv].View(),
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
