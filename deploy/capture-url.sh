#!/bin/sh
mkdir -p "$HOME/.gp-web"
printf '%s\n' "$1" > "$HOME/.gp-web/login-url"
