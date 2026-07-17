package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	telegramAPIBase        = "https://api.telegram.org/bot"
	defaultWatchInterval   = 24 * time.Hour
	minimumWatchInterval   = time.Minute
	telegramMessageMaxSize = 3900
)

type TelegramBot struct {
	token        string
	client       *http.Client
	watchersFile string
	watchers     map[string]watcherEntry
	watchersMu   sync.Mutex
}

type WatchConfig struct {
	ChatID          int64  `json:"chat_id"`
	Target          string `json:"target"`
	IntervalSeconds int64  `json:"interval_seconds"`
}

type watcherEntry struct {
	Config WatchConfig
	Cancel context.CancelFunc
}

type TelegramUpdate struct {
	UpdateID int             `json:"update_id"`
	Message  TelegramMessage `json:"message"`
}

type TelegramMessage struct {
	Chat TelegramChat `json:"chat"`
	Text string       `json:"text"`
}

type TelegramChat struct {
	ID int64 `json:"id"`
}

type updatesResponse struct {
	OK     bool             `json:"ok"`
	Result []TelegramUpdate `json:"result"`
}

type sendMessageRequest struct {
	ChatID                int64  `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func main() {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("Set TELEGRAM_BOT_TOKEN environment variable")
	}
	bot := NewTelegramBot(token)
	if err := bot.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func NewTelegramBot(token string) *TelegramBot {
	return &TelegramBot{
		token:        token,
		client:       &http.Client{Timeout: 70 * time.Second},
		watchersFile: defaultWatchersPath(),
		watchers:     make(map[string]watcherEntry),
	}
}

func (bot *TelegramBot) Run(ctx context.Context) error {
	if err := bot.restoreWatchers(); err != nil {
		log.Printf("restore watchers failed: %v", err)
	}
	log.Println("ssl-checker Telegram bot started")
	offset := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		updates, err := bot.getUpdates(ctx, offset)
		if err != nil {
			log.Printf("getUpdates failed: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		for _, update := range updates {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}
			bot.handleUpdate(ctx, update)
		}
	}
}

func (bot *TelegramBot) handleUpdate(ctx context.Context, update TelegramUpdate) {
	message := update.Message
	text := strings.TrimSpace(message.Text)
	if message.Chat.ID == 0 || text == "" {
		return
	}
	fields := strings.Fields(text)
	command := strings.Split(fields[0], "@")[0]
	args := fields[1:]

	switch command {
	case "/start", "/help":
		bot.sendMessage(ctx, message.Chat.ID, helpText())
	case "/check":
		if len(args) == 0 {
			bot.sendMessage(ctx, message.Chat.ID, "Использование: /check example.com или /check https://example.com:443")
			return
		}
		bot.sendMessage(ctx, message.Chat.ID, "Проверяю "+args[0]+"...")
		bot.runCheckAndSend(ctx, message.Chat.ID, args[0])
	case "/watch":
		bot.watch(ctx, message.Chat.ID, args)
	case "/unwatch":
		bot.unwatch(ctx, message.Chat.ID, args)
	case "/list":
		bot.listWatchers(ctx, message.Chat.ID)
	default:
		bot.sendMessage(ctx, message.Chat.ID, "Неизвестная команда. Используйте /help.")
	}
}

func (bot *TelegramBot) watch(ctx context.Context, chatID int64, args []string) {
	if len(args) == 0 {
		bot.sendMessage(ctx, chatID, "Использование: /watch example.com [интервал_в_минутах]")
		return
	}
	target := args[0]
	if _, _, err := NormalizeTarget(target); err != nil {
		bot.sendMessage(ctx, chatID, "Ошибка: "+err.Error())
		return
	}
	interval := defaultWatchInterval
	if len(args) > 1 {
		minutes, err := strconv.Atoi(args[1])
		if err != nil {
			bot.sendMessage(ctx, chatID, "Интервал должен быть целым числом минут.")
			return
		}
		interval = time.Duration(minutes) * time.Minute
	}
	if interval < minimumWatchInterval {
		interval = minimumWatchInterval
	}

	config := WatchConfig{ChatID: chatID, Target: target, IntervalSeconds: int64(interval.Seconds())}
	bot.upsertWatcher(config)
	if err := bot.saveWatchers(); err != nil {
		bot.sendMessage(ctx, chatID, "⚠️ Проверка добавлена, но не удалось сохранить список проверок: "+err.Error())
		return
	}
	bot.sendMessage(ctx, chatID, fmt.Sprintf("✅ Добавлена проверка %s каждые %s.", target, formatInterval(interval)))
}

func (bot *TelegramBot) watchLoop(ctx context.Context, chatID int64, target string, interval time.Duration) {
	bot.runScheduledCheckAndAlert(ctx, chatID, target)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bot.runScheduledCheckAndAlert(ctx, chatID, target)
		}
	}
}

func (bot *TelegramBot) unwatch(ctx context.Context, chatID int64, args []string) {
	if len(args) == 0 {
		bot.sendMessage(ctx, chatID, "Использование: /unwatch example.com")
		return
	}
	key := watcherKey(chatID, args[0])
	bot.watchersMu.Lock()
	entry, ok := bot.watchers[key]
	if ok {
		entry.Cancel()
		delete(bot.watchers, key)
	}
	bot.watchersMu.Unlock()
	if ok {
		if err := bot.saveWatchers(); err != nil {
			bot.sendMessage(ctx, chatID, "⚠️ Проверка удалена, но не удалось сохранить список проверок: "+err.Error())
			return
		}
		bot.sendMessage(ctx, chatID, "✅ Проверка удалена.")
	} else {
		bot.sendMessage(ctx, chatID, "Активная проверка не найдена.")
	}
}

func (bot *TelegramBot) listWatchers(ctx context.Context, chatID int64) {
	prefix := fmt.Sprintf("%d:", chatID)
	bot.watchersMu.Lock()
	defer bot.watchersMu.Unlock()
	var targets []string
	for key, entry := range bot.watchers {
		if strings.HasPrefix(key, prefix) {
			interval := time.Duration(entry.Config.IntervalSeconds) * time.Second
			targets = append(targets, fmt.Sprintf("- %s — каждые %s", entry.Config.Target, formatInterval(interval)))
		}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		bot.sendMessage(ctx, chatID, "Активных проверок нет.")
		return
	}
	bot.sendMessage(ctx, chatID, "Активные проверки:\n"+strings.Join(targets, "\n"))
}

func (bot *TelegramBot) runCheckAndSend(ctx context.Context, chatID int64, target string) {
	result, err := CheckTLSCertificate(ctx, target)
	message := ""
	if err != nil {
		message = fmt.Sprintf("❌ Ошибка TLS проверки %s: %v", target, err)
	} else {
		message = FormatResult(result)
	}
	bot.sendLongMessage(ctx, chatID, message)
}

func (bot *TelegramBot) runScheduledCheckAndAlert(ctx context.Context, chatID int64, target string) {
	result, err := CheckTLSCertificate(ctx, target)
	if err != nil {
		bot.sendLongMessage(ctx, chatID, fmt.Sprintf("🚨 TLS alert for %s\n❌ Ошибка TLS проверки: %v", target, err))
		return
	}
	if len(result.Problems) == 0 {
		log.Printf("scheduled TLS check succeeded for %s without warnings", target)
		return
	}
	bot.sendLongMessage(ctx, chatID, "🚨 TLS alert for "+target+"\n"+FormatResult(result))
}

func (bot *TelegramBot) sendLongMessage(ctx context.Context, chatID int64, message string) {
	for _, chunk := range splitMessage(message, telegramMessageMaxSize) {
		bot.sendMessage(ctx, chatID, chunk)
	}
}

func (bot *TelegramBot) getUpdates(ctx context.Context, offset int) ([]TelegramUpdate, error) {
	endpoint := fmt.Sprintf("%s%s/getUpdates?timeout=60&offset=%d", telegramAPIBase, bot.token, offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := bot.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload updatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if !payload.OK {
		return nil, fmt.Errorf("Telegram API returned ok=false")
	}
	return payload.Result, nil
}

func (bot *TelegramBot) sendMessage(ctx context.Context, chatID int64, text string) {
	body, err := json.Marshal(sendMessageRequest{ChatID: chatID, Text: text, DisableWebPagePreview: true})
	if err != nil {
		log.Printf("sendMessage marshal failed: %v", err)
		return
	}
	endpoint := telegramAPIBase + bot.token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("sendMessage request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := bot.client.Do(req)
	if err != nil {
		log.Printf("sendMessage failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("sendMessage returned HTTP %s", resp.Status)
	}
}

func (bot *TelegramBot) upsertWatcher(config WatchConfig) {
	key := watcherKey(config.ChatID, config.Target)
	watchCtx, cancel := context.WithCancel(context.Background())
	bot.watchersMu.Lock()
	if existing, ok := bot.watchers[key]; ok {
		existing.Cancel()
	}
	bot.watchers[key] = watcherEntry{Config: config, Cancel: cancel}
	bot.watchersMu.Unlock()
	go bot.watchLoop(watchCtx, config.ChatID, config.Target, time.Duration(config.IntervalSeconds)*time.Second)
}

func (bot *TelegramBot) restoreWatchers() error {
	configs, err := bot.loadWatcherConfigs()
	if err != nil {
		return err
	}
	for _, config := range configs {
		if config.IntervalSeconds < int64(minimumWatchInterval.Seconds()) {
			config.IntervalSeconds = int64(minimumWatchInterval.Seconds())
		}
		bot.upsertWatcher(config)
	}
	if len(configs) > 0 {
		log.Printf("restored %d scheduled TLS checks", len(configs))
	}
	return nil
}

func (bot *TelegramBot) loadWatcherConfigs() ([]WatchConfig, error) {
	var lastErr error
	for _, path := range watcherPathCandidates(bot.watchersFile) {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			lastErr = err
			continue
		}
		var configs []WatchConfig
		if err := json.Unmarshal(data, &configs); err != nil {
			return nil, err
		}
		bot.watchersFile = path
		return configs, nil
	}
	return nil, lastErr
}

func (bot *TelegramBot) saveWatchers() error {
	bot.watchersMu.Lock()
	configs := make([]WatchConfig, 0, len(bot.watchers))
	for _, entry := range bot.watchers {
		configs = append(configs, entry.Config)
	}
	bot.watchersMu.Unlock()
	sort.Slice(configs, func(i, j int) bool {
		if configs[i].ChatID == configs[j].ChatID {
			return configs[i].Target < configs[j].Target
		}
		return configs[i].ChatID < configs[j].ChatID
	})
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return err
	}
	var lastErr error
	for _, path := range watcherPathCandidates(bot.watchersFile) {
		if err := writeWatchersFile(path, data); err != nil {
			lastErr = err
			log.Printf("failed to save watchers to %s: %v", path, err)
			continue
		}
		if path != bot.watchersFile {
			log.Printf("watchers storage fallback activated: %s", path)
		}
		bot.watchersFile = path
		return nil
	}
	return lastErr
}

func writeWatchersFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func defaultWatchersPath() string {
	if watchersFile := os.Getenv("WATCHERS_FILE"); watchersFile != "" {
		return watchersFile
	}
	return defaultConfigWatchersPath()
}

func watcherPathCandidates(primary string) []string {
	paths := []string{primary}
	if configPath := defaultConfigWatchersPath(); configPath != "" {
		paths = append(paths, configPath)
	}
	paths = append(paths, fallbackWatchersPath())

	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		unique = append(unique, path)
	}
	return unique
}

func defaultConfigWatchersPath() string {
	configDir, err := os.UserConfigDir()
	if err == nil && configDir != "" {
		return filepath.Join(configDir, "ssl-checker", "watchers.json")
	}
	return fallbackWatchersPath()
}

func fallbackWatchersPath() string {
	return filepath.Join(os.TempDir(), "ssl-checker", "watchers.json")
}

func watcherKey(chatID int64, target string) string {
	return fmt.Sprintf("%d:%s", chatID, strings.ToLower(strings.TrimSpace(target)))
}

func formatInterval(interval time.Duration) string {
	if interval%time.Hour == 0 {
		hours := int(interval.Hours())
		return fmt.Sprintf("%d ч", hours)
	}
	if interval%time.Minute == 0 {
		minutes := int(interval.Minutes())
		return fmt.Sprintf("%d мин", minutes)
	}
	return interval.String()
}

func splitMessage(text string, limit int) []string {
	if text == "" {
		return []string{""}
	}
	var chunks []string
	for len(text) > limit {
		cut := strings.LastIndex(text[:limit], "\n")
		if cut <= 0 {
			cut = limit
		}
		chunks = append(chunks, text[:cut])
		text = strings.TrimLeft(text[cut:], "\n")
	}
	return append(chunks, text)
}

func helpText() string {
	return "Бот проверяет TLS/SSL сертификат сайта, доверенную цепочку, сроки, SAN, issuer, fingerprint, протокол и шифр.\n\n" +
		"Команды:\n" +
		"/check <url|host[:port]> — разовая проверка\n" +
		"/watch <url|host[:port]> [минуты] — проверять по таймеру\n" +
		"/list — список активных проверок\n" +
		"/unwatch <url|host[:port]> — удалить таймер"
}
