#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Switch the OS appearance to test Wireshark's System/Light/Dark handling.
#
# Usage: set-appearance.sh [system|light|dark]
# Without an argument the current setting is printed.

set -e

usage() {
    echo "Usage: $0 [system|light|dark]" >&2
    exit 1
}

mode=""
if [ $# -gt 1 ]; then
    usage
fi
if [ $# -eq 1 ]; then
    mode=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$mode" in
        system|light|dark) ;;
        *) usage ;;
    esac
fi

darwin_current() {
    auto=$(defaults read -g AppleInterfaceStyleSwitchesAutomatically 2>/dev/null || echo 0)
    style=$(defaults read -g AppleInterfaceStyle 2>/dev/null || echo Light)
    if [ "$auto" = "1" ]; then
        echo "system"
    elif [ "$style" = "Dark" ]; then
        echo "dark"
    else
        echo "light"
    fi
}

darwin_set_dark_mode() {
    osascript -e "tell application \"System Events\" to tell appearance preferences to set dark mode to $1"
}

darwin() {
    case "$mode" in
        "")
            darwin_current
            ;;
        light|dark)
            defaults write -g AppleInterfaceStyleSwitchesAutomatically -bool false
            if [ "$mode" = "dark" ]; then
                darwin_set_dark_mode true
            else
                darwin_set_dark_mode false
            fi
            ;;
        system)
            defaults write -g AppleInterfaceStyleSwitchesAutomatically -bool true
            defaults delete -g AppleInterfaceStyle 2>/dev/null || true
            echo "Running applications follow at the next automatic switch or after logging in again."
            ;;
    esac
}

gnome_schema() {
    command -v gsettings >/dev/null 2>&1 &&
        gsettings list-keys org.gnome.desktop.interface 2>/dev/null | grep -qx color-scheme
}

gnome_current() {
    case "$(gsettings get org.gnome.desktop.interface color-scheme)" in
        *prefer-dark*) echo "dark" ;;
        *prefer-light*) echo "light" ;;
        *) echo "system" ;;
    esac
}

gnome_set() {
    # Older schemas lack prefer-light; fall back to default.
    gsettings set org.gnome.desktop.interface color-scheme "$1" 2>/dev/null ||
        gsettings set org.gnome.desktop.interface color-scheme default
}

linux() {
    if gnome_schema; then
        case "$mode" in
            "") gnome_current ;;
            light) gnome_set prefer-light ;;
            dark) gnome_set prefer-dark ;;
            system) gnome_set default ;;
        esac
    elif command -v plasma-apply-colorscheme >/dev/null 2>&1; then
        case "$mode" in
            "") echo "Not queried on KDE Plasma; use plasma-apply-colorscheme --list-schemes." ;;
            light) plasma-apply-colorscheme BreezeLight ;;
            dark) plasma-apply-colorscheme BreezeDark ;;
            system)
                echo "Plasma has no automatic mode; applying BreezeLight."
                plasma-apply-colorscheme BreezeLight
                ;;
        esac
    else
        echo "This desktop is not supported." >&2
        exit 1
    fi
}

case "$(uname -s)" in
    Darwin) darwin ;;
    Linux) linux ;;
    *)
        echo "Unsupported OS; on Windows use set-appearance.ps1." >&2
        exit 1
        ;;
esac
