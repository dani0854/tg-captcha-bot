<a href="https://goreportcard.com/report/github.com/dani0854/tg-captcha-bot"><img src="https://goreportcard.com/badge/github.com/dani0854/tg-captcha-bot" alt="Go Report Card"></a>
<img src="https://img.shields.io/github/go-mod/go-version/dani0854/tg-captcha-bot" alt="Version">
<a href="https://github.com/dani0854/tg-captcha-bot/issues"><img alt="GitHub closed issues" src="https://img.shields.io/github/issues-closed-raw/dani0854/tg-captcha-bot"></a>
<a href="https://github.com/dani0854/tg-captcha-bot/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/dani0854/tg-captcha-bot"></a>

# Telegram Captcha Bot

Telegram bot that validates new users that enter supergroup. Validation works like a simple captcha. Bot written in Go (Golang).

This bot has been tested on several supergroups (1000+ people) for a long time and has shown its effectiveness against spammers.

## How it works

1. Add the bot to your supergroup
2. Promote the bot for administrator privileges
3. A new user enters your supergroup
4. Bot restricts the user's ability to send messages
5. Bot shows a welcome message and a captcha button to the user
6. If the user doesn't press the button within 30 seconds then the user is banned by the bot

## Commands

`/healthz` - check that the bot is working correctly

## Сustomization

You can change several bot's settings (welcome message, ban duration, socks5 proxy server) through the configuration file `config.toml`
