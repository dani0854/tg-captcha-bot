package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/rand"

	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	tele "gopkg.in/telebot.v3"
)

// Config struct for toml config file
type Config struct {
	ButtonText               string  `mapstructure:"button_text"`
	WelcomeMessage           string  `mapstructure:"welcome_message"`
	WelcomeImages            bool    `mapstructure:"welcome_images"`
	AfterSuccessMessage      string  `mapstructure:"after_success_message"`
	AfterFailMessage         string  `mapstructure:"after_fail_message"`
	AllowedGroupIds          []int64 `mapstructure:"allowed_group_ids"`
	PrintSuccessAndFail      string  `mapstructure:"print_success_and_fail_messages_strategy"`
	DeleteJoinMessages       string  `mapstructure:"delete_join_messages"`
	WelcomeTimeout           string  `mapstructure:"welcome_timeout"`
	BanDurations             string  `mapstructure:"ban_duration"`
	HealthMessage            string  `mapstructure:"health_message"`
	WrongPersonResponse      string  `mapstructure:"wrong_person_response"`
	ValidationPassedResponse string  `mapstructure:"validation_passed_response"`
	UseSocks5Proxy           string  `mapstructure:"use_socks5_proxy"`
	Socks5Address            string  `mapstructure:"socks5_address"`
	Socks5Port               string  `mapstructure:"socks5_port"`
	Socks5Login              string  `mapstructure:"socks5_login"`
	Socks5Password           string  `mapstructure:"socks5_password"`
}

const tgTokenEnv = "TGTOKEN"
const configPathEnv = "CONFIG_PATH"
const imagesPathEnv = "IMAGES_PATH"
const logLevelEnv = "LOG_LEVEL"

var allowedUpdates = []string{
	"message",
	"callback_query",
	"chat_member",
}

var config Config
var b *tele.Bot
var passedUsers = sync.Map{}
var joinMessages = sync.Map{}
var images [][]byte

func init() {
	err := initLogger()
	if err != nil {
		fmt.Printf("[ERROR] Couldn't initialize logger: %v", err)
		os.Exit(1)
	}
}

func main() {
	err := initConfig()
	if err != nil {
		slog.Error("Couldn't initialize config", "error", err)
		os.Exit(1)
	}

	err = initBot()
	if err != nil {
		slog.Error("Couldn't initialize bot", "error", err)
		os.Exit(1)
	}

	if config.WelcomeImages {
		err = initImages()
		if err != nil {
			slog.Error("Couldn't initialize images", "error", err)
			os.Exit(1)
		}

	}

	err = setupCaptchaChallange()
	if err != nil {
		slog.Error("Couldn't setup captcha challenge", "error", err)
		os.Exit(1)
	}

	// Leave if group not in a whitelist
	if len(config.AllowedGroupIds) != 0 {
		b.Handle(tele.OnAddedToGroup, func(c tele.Context) error {
			if !slices.Contains(config.AllowedGroupIds, c.Chat().ID) {
				slog.Warn("Chat is not in allowed group ID's, leaving", "chat_id", c.Chat().ID)
				return b.Leave(c.Chat())
			}
			return nil
		})
	}

	// Print health message
	b.Handle("/healthz", func(c tele.Context) error {
		slog.Info("Healthz requested", "from_username", getUsername(c.Sender()), "chat_id", c.Chat().ID)
		slog.Debug("Healthz requested", "from", c.Sender(), "chat", c.Chat())
		return c.Send(config.HealthMessage)
	})

	go func() {
		b.Start()
	}()
	slog.Info("Bot started!")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	slog.Info("Shutdown signal received, exiting...")
}

func setupCaptchaChallange() (err error) {
	// Extract weclome timeout duration
	timeoutDuration, err := strconv.ParseInt(config.WelcomeTimeout, 10, 64)
	if err != nil {
		err = fmt.Errorf("Cannot parse timeout duration '%v': %w", config.WelcomeTimeout, err)
		return
	}

	captchaButton := tele.InlineButton{
		Unique: "challenge_btn",
		Text:   config.ButtonText,
	}

	if config.DeleteJoinMessages != "never" {
		b.Handle(tele.OnUserJoined, func(c tele.Context) error {
			message := c.Message()
			if message == nil {
				return fmt.Errorf("Join message is nil in '%v'", c)
			}

			joinMessages.Store(message.UserJoined.ID, message)

			return nil
		})
	}

	b.Handle(tele.OnChatMember, func(c tele.Context) (err error) {
		// Check if group allowed
		if len(config.AllowedGroupIds) != 0 && !slices.Contains(config.AllowedGroupIds, c.Chat().ID) {
			slog.Warn("Chat not in allowed group ID's, not trying to challenge user", "chat", c.Chat())
			return b.Leave(c.Chat())
		}

		if !(c.ChatMember().OldChatMember.Role == "left" && c.ChatMember().NewChatMember.Role == "member") {
			slog.Debug("Not a join update", "chat_member_old", c.ChatMember().OldChatMember, "chat_member_new", c.ChatMember().NewChatMember)
			return
		}

		user := c.ChatMember().NewChatMember.User
		username := getUsername(user)

		slog.Info("User joined the chat", "from_username", username, "chat_id", c.Chat().ID)
		slog.Debug("User joined the chat", "user", c.ChatMember(), "chat", c.Chat())

		// Set restriction duration incase bot fails
		restrictionDuration := time.Now().Add(2 * time.Duration(timeoutDuration) * time.Second).Unix()
		restrictedChatMember := tele.ChatMember{User: c.ChatMember().NewChatMember.User, RestrictedUntil: restrictionDuration, Rights: tele.Rights{CanSendMessages: false}}

		// Restrict user upon entry
		err = b.Restrict(c.Chat(), &restrictedChatMember)
		if err != nil {
			err = fmt.Errorf("Couldn't restrict user: %w", err)
			return
		}

		// Create personolised text message

		messageText := username + config.WelcomeMessage

		mention := []tele.MessageEntity{
			{
				Type:   tele.EntityTMention,
				Length: utf8.RuneCountInString(username),
				User:   user,
			},
		}
		slog.Debug("Created mention", "mention", mention)

		var message interface{}
		if config.WelcomeImages {
			// Get random image
			image := images[rand.Intn(len(images))]

			message = &tele.Photo{
				File:    tele.FromReader(bytes.NewReader(image)),
				Caption: messageText,
			}
		} else {
			message = messageText
		}

		msg, err := b.Send(c.Chat(), message, &tele.SendOptions{Entities: mention, ReplyMarkup: &tele.ReplyMarkup{InlineKeyboard: [][]tele.InlineButton{{captchaButton}}}})
		if err != nil {
			err = fmt.Errorf("Can't send challenge msg: %w", err)
			return
		}

		scheduleTimeout(c.Chat(), user, msg, timeoutDuration)

		return
	})

	b.Handle(&captchaButton, func(c tele.Context) (err error) {
		var entities tele.Entities
		if config.WelcomeImages {
			entities = c.Callback().Message.CaptionEntities
		} else {
			entities = c.Callback().Message.Entities
		}
		var user *tele.User
		for _, entity := range entities {
			if entity.User != nil {
				user = entity.User
				break
			}
		}
		if user == nil {
			slog.Debug("No entities in message", "message", c.Callback().Message)
			err = fmt.Errorf("No entities in message")
			// Incase entities not found, don't ban the user
			passedUsers.Store(c.Callback().Sender.ID, struct{}{})
			return
		}

		if user.ID != c.Callback().Sender.ID {
			return c.Respond(&tele.CallbackResponse{Text: config.WrongPersonResponse})
		}

		passedUsers.Store(user.ID, struct{}{})

		if config.PrintSuccessAndFail == "show" {
			_, err := b.Edit(c.Callback().Message, config.AfterSuccessMessage)
			if err != nil {
				slog.Error("Couldn't edit message", "message", c.Callback().Message, "error", err)
			}
		} else if config.PrintSuccessAndFail == "del" {
			err := b.Delete(c.Callback().Message)
			if err != nil {
				slog.Error("Couldn't delete message", "message", c.Callback().Message, "error", err)
			}
		}

		slog.Info("User passed challenge", "username", getUsername(user), "chat_id", c.Chat().ID)
		newChatMember := tele.ChatMember{User: user, RestrictedUntil: tele.Forever(), Rights: tele.Rights{CanSendMessages: true}}
		err = b.Promote(c.Chat(), &newChatMember)
		if err != nil {
			err = fmt.Errorf("Couldn't promote user: %w", err)
			return
		}

		err = c.Respond(&tele.CallbackResponse{Text: config.ValidationPassedResponse})
		if err != nil {
			slog.Error("Couldn't respond", "callback", c.Callback(), "error", err)
		}

		if config.DeleteJoinMessages == "always" {
			err = deleteJoinMessageIfExists(user.ID)
			if err != nil {
				slog.Error("Couldn't delete join message", "error", err)
			}
		} else if config.DeleteJoinMessages != "never" {
			joinMessages.Delete(user.ID)
		}

		return
	})

	return
}

func scheduleTimeout(chat *tele.Chat, user *tele.User, msg *tele.Message, timeoutDuration int64) {
	time.AfterFunc(time.Duration(timeoutDuration)*time.Second, func() {
		_, passed := passedUsers.LoadAndDelete(user.ID)
		if passed {
			slog.Debug("User passed, timeout canceled", "user_id", user.ID)
			return
		}

		// Get ban duration
		banDuration, err := getBanDuration()
		if err != nil {
			slog.Error("Can't get ban duration", "error", err)
			return
		}

		chatMember := tele.ChatMember{User: user, RestrictedUntil: banDuration}
		err = b.Ban(chat, &chatMember)
		if err != nil {
			slog.Error("Couldn't ban user", "user", user, "chat", chat, "error", err)
			return
		}

		if config.PrintSuccessAndFail == "show" {
			_, err := b.Edit(msg, config.AfterFailMessage)
			if err != nil {
				slog.Error("Couldn't edit message", "message", msg, "error", err)
			}
		} else if config.PrintSuccessAndFail == "del" {
			err = b.Delete(msg)
			if err != nil {
				slog.Error("Couldn't delete message", "message", msg, "error", err)
			}
		}

		if config.DeleteJoinMessages == "on-fail" || config.DeleteJoinMessages == "always" {
			err = deleteJoinMessageIfExists(user.ID)
			if err != nil {
				slog.Error("Couldn't delete join message", "error", err)
			}
		}

		slog.Info("User banned in chat", "username", getUsername(user), "chat_id", chat.ID, "until", time.Unix(banDuration, 0).UTC())
	})
}

func deleteJoinMessageIfExists(userID int64) (err error) {
	value, ok := joinMessages.LoadAndDelete(userID)
	if !ok {
		slog.Debug("Join message not found", "user_id", userID)
	}

	joinMessage, ok := value.(*tele.Message)
	if !ok {
		err = fmt.Errorf("Incorrect type '%v'", value)
		return
	}

	err = b.Delete(joinMessage)
	if err != nil {
		err = fmt.Errorf("Couldn't delete join message: %w", err)
		return
	}
	return
}

func getUsername(user *tele.User) string {
	username := user.FirstName
	if user.LastName != "" {
		username = username + " " + user.LastName
	}
	if user.Username != "" {
		username = username + " (@" + user.Username + ")"
	}

	return username
}

func initLogger() (err error) {
	// Default
	logLevel := slog.LevelInfo

	logLevelString, ok := os.LookupEnv(logLevelEnv)
	if ok {
		err = logLevel.UnmarshalText([]byte(logLevelString))
		if err != nil {
			return
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	slog.SetDefault(logger)
	return
}

func initConfig() (err error) {
	v := viper.New()
	v.SetConfigName("config")
	path, ok := os.LookupEnv(configPathEnv)
	if ok {
		slog.Info("Using config path from environment variable", "var_name", configPathEnv, "path", path)
		v.AddConfigPath(path)
	} else {
		slog.Info("Using default config path")
		v.AddConfigPath(".")
	}

	err = v.ReadInConfig()
	if err != nil {
		err = fmt.Errorf("Couldn't read config: %w", err)
		return
	}

	err = v.Unmarshal(&config)
	if err != nil {
		err = fmt.Errorf("Couldn't umarshal config: %w", err)
		return
	}

	slog.Debug("Config loaded", "config", config)
	return
}

func initBot() (err error) {
	token, err := getToken(tgTokenEnv)
	if err != nil {
		err = fmt.Errorf("Couldn't obtain telegram bot token: %w", err)
		return
	}
	slog.Info("Telegram bot token obtained", "token", token)

	var httpClient *http.Client
	if config.UseSocks5Proxy == "yes" {
		slog.Info("Using proxy")
		httpClient, err = initSocks5Client()
		if err != nil {
			err = fmt.Errorf("Couldn't init socks5 proxy: %w", err)
			return
		}
		slog.Debug("Initialized proxy", "http_client", httpClient)
	}

	b, err = tele.NewBot(tele.Settings{
		Token: token,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second,
			AllowedUpdates: allowedUpdates,
			// Temp fix for https://github.com/tucnak/telebot/issues/640
			LastUpdateID: -2,
		},
		Client: httpClient,
		OnError: func(err error, c tele.Context) {
			slog.Error("Error during handling", "error", err, "context", c)
		},
	})
	if err != nil {
		err = fmt.Errorf("Couldn't create bot: %w", err)
		return
	}
	slog.Debug("Bot created", "bot", b)

	return
}

func getToken(key string) (token string, err error) {
	token, ok := os.LookupEnv(key)
	if !ok {
		err = fmt.Errorf("Env variable '%v' isn't set!", key)
		return
	}
	match, err := regexp.MatchString(`^[0-9]+:.*$`, token)
	if err != nil {
		return
	}
	if !match {
		err = fmt.Errorf("Telegram Bot Token '%v' is incorrect. Token doesn't comply with regexp: `^[0-9]+:.*$`.", token)
		return
	}
	return
}

func initImages() (err error) {
	imagesPath, ok := os.LookupEnv(imagesPathEnv)
	if ok {
		slog.Info("Using images path from environment variable", "var_name", imagesPathEnv, "path", imagesPath)
	} else {
		slog.Info("Using default images path")
		imagesPath = "./images"
	}

	files, err := os.ReadDir(imagesPath)
	if err != nil {
		err = fmt.Errorf("Error reading directory: %w", err)
		return
	}

	filterRE, err := regexp.Compile(`\.(?:jpg|png)$`)
	if err != nil {
		err = fmt.Errorf("Error compiling filter regex: %w", err)
		return
	}

	for _, file := range files {
		imageName := file.Name()
		imagePath := filepath.Join(imagesPath, file.Name())

		match := filterRE.MatchString(imageName)
		if !match {
			slog.Debug("File extension not supported as image", "image_path", imagePath)
			continue
		}

		slog.Debug("Reading image", "image_path", imagePath)
		image, err := os.ReadFile(imagePath)
		if err != nil {
			err = fmt.Errorf("Can't open image: %w", err)
			return err
		}
		images = append(images, image)
	}

	if len(images) == 0 {
		err = fmt.Errorf("No images found in the images directory")
		return
	}

	slog.Info("Loaded images", "count", len(images))

	return
}

func getBanDuration() (duration int64, err error) {
	if config.BanDurations == "forever" {
		duration = tele.Forever()
		return
	}

	n, err := strconv.ParseInt(config.BanDurations, 10, 64)
	if err != nil {
		err = fmt.Errorf("Couldn't parse ban duration '%v': %w", config.BanDurations, err)
		return
	}

	duration = time.Now().Add(time.Duration(n) * time.Minute).Unix()

	return
}

func initSocks5Client() (httpClient *http.Client, err error) {
	addr := fmt.Sprintf("%s:%s", config.Socks5Address, config.Socks5Port)
	dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{User: config.Socks5Login, Password: config.Socks5Password}, proxy.Direct)
	if err != nil {
		err = fmt.Errorf("Couldn't init socks5 proxy client dialer: %w", err)
		return
	}

	httpTransport := &http.Transport{}
	httpClient = &http.Client{Transport: httpTransport}
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}

	httpTransport.DialContext = dialContext

	return
}
