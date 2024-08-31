package showcredentials

import (
	"context"
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/MaximMNsk/go-secure-storage/client/storage/remote"
	"github.com/MaximMNsk/go-secure-storage/internal/messages"
	pb "github.com/MaximMNsk/go-secure-storage/proto"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

var blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
var quitTextStyle = lipgloss.NewStyle().Margin(1, 0, 2, 4)

type Model struct {
	table table.Model
}

// Init - инициализация объекта TUI перед запуском.
func (m Model) Init() tea.Cmd { return nil }

// Update - обработка событий клавиатуры.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "ctrl+home", "home":
			go func() {
				RouterProxyChan <- new(messages.Message).GetPrimaryRoute()
			}()
			return m, tea.Quit
		case "q", "ctrl+c":
			Message = `Good bye!`
			go func() {
				RouterProxyChan <- new(messages.Message).GetExitRoute()
			}()
			return m, tea.Quit
		case "enter":
			Message = fmt.Sprintf("%s, %s, %s",
				ListCreds[m.table.SelectedRow()[0]].Source,
				ListCreds[m.table.SelectedRow()[0]].Login,
				ListCreds[m.table.SelectedRow()[0]].Password,
			)
			return m, nil
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// View - определение отображения интерфейса пользователя.
func (m Model) View() string {
	return quitTextStyle.Render(Message) + "\n" + baseStyle.Render(m.table.View()) + "\n\n  " + m.table.HelpView() + "\n\n" + blurredStyle.Render("ctrl+home to back")
}

var (
	RouterProxyChan chan messages.Message
	ServerStorage   remote.Storage
	Token           string
	Message         string
	ListCreds       map[string]*pb.Credentials
)

// Show - запуск интерфейса.
func (m Model) Show(storage remote.Storage, routerCh chan messages.Message, token string) error {
	RouterProxyChan = routerCh
	ServerStorage = storage
	Token = token

	if len(Token) == 0 {
		RouterProxyChan <- messages.NewMessage(messages.Route, messages.RouteStart, `unauthorized action`)
		return nil
	}

	if !storage.Ping(context.Background()) {
		RouterProxyChan <- messages.NewMessage(messages.Route, messages.RoutePrimary, `service unavailable!!!`)
		return nil
	}

	creds, err := ServerStorage.GetCredentials(context.Background(), Token)
	if err != nil {
		Message = err.Error()
	}

	listCreds := make(map[string]*pb.Credentials)
	var rows []table.Row

	columns := []table.Column{
		{Title: "Credentials source", Width: 50},
	}

	for _, cred := range creds {
		rows = append(rows, table.Row{cred.Source})
		listCreds[cred.Source] = cred
	}

	ListCreds = listCreds

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(7),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	mm := Model{t}
	if _, err := tea.NewProgram(mm).Run(); err != nil {
		return err
	}

	return nil
}
