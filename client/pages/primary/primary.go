package primary

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/MaximMNsk/go-secure-storage/client/storage/remote"
	"github.com/MaximMNsk/go-secure-storage/internal/messages"
)

const listHeight = 14

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	startHelpStyle    = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type Menu struct {
	list     list.Model
	quitting bool
}

// Init - инициализация объекта TUI перед запуском.
func (m *Menu) Init() tea.Cmd {
	return nil
}

// Update - обработка событий клавиатуры.
func (m *Menu) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			go func() {
				ProxyRouterChan <- new(messages.Message).GetExitRoute()
			}()
			return m, tea.Quit

		case "enter":
			m.quitting = true
			i, ok := m.list.SelectedItem().(item)
			if ok {
				go func() {
					ProxyRouterChan <- messages.NewMessage(messages.Route, messages.PrepareRoute(string(i)), ``)
				}()
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View - определение отображения интерфейса пользователя.
func (m *Menu) View() string {
	return quitTextStyle.Render(Message) + "\n" + m.list.View()
}

const (
	defaultTitle     = `Authorized actions:`
	unavailableTitle = `Service unavailable!!!`
	defaultWidth     = 20
)

var ProxyRouterChan chan messages.Message
var Message string
var Token string

// Show - запуск интерфейса.
func (m *Menu) Show(storage remote.Storage, routerCh chan messages.Message, token, mess string) error {
	ProxyRouterChan = routerCh
	Message = mess
	Token = token

	items := []list.Item{
		item("Show cards"),
		item("Add card"),
		item("Show credentials"),
		item("Add credentials"),
		item("Show plains"),
		item("Add plain"),
		item("Show files"),
		item("Add file"),
		item("Exit"),
	}

	title := defaultTitle

	if !storage.Ping(context.Background()) {
		items = []list.Item{
			item("Exit"),
		}
		title = unavailableTitle
	}

	l := list.New(items, itemDelegate{}, defaultWidth, listHeight)
	l.Title = title
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = startHelpStyle

	mm := Menu{list: l}

	if _, err := tea.NewProgram(&mm).Run(); err != nil {
		return err
	}
	return nil
}
