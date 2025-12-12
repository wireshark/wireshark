#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Configure local git template/hooks for Wireshark development.

set -e

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

echo "Setting commit template to .gitmessage"
git config commit.template "$repo_root/.gitmessage"

echo "Setting hooks path to tools/git_hooks"
git config core.hooksPath "$repo_root/tools/git_hooks"

name="$(git config user.name || true)"
email="$(git config user.email || true)"

if [ -z "$name" ] || [ -z "$email" ]; then
    cat <<'EOF'
Git user.name or user.email is not set.
To configure your name and email for git, run:

  git config --global user.name "Your Name"
  git config --global user.email "you@example.com"

After that update the author of your latest commit with:

  git commit --amend --reset-author --no-edit
EOF
    exit 1
else
    echo "Git user configured as: $name <$email>"
fi

echo "Done. Hooks and commit template are configured for this repository."

os_name="$(uname -s 2>/dev/null || echo unknown)"
platform_script=""
platform_label=""

case "$os_name" in
    Darwin)
        platform_label="macOS"
        # Let the user pick brew (default) or non-brew.
        ;;
    MINGW*|MSYS*)
        platform_label="Windows/MSYS2"
        platform_script="$repo_root/tools/msys2-setup.sh"
        ;;
    *)
        # Assume Linux-ish; try os-release
        if [ -r /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                alpine) platform_label="Linux (Alpine)"; platform_script="$repo_root/tools/alpine-setup.sh" ;;
                arch) platform_label="Linux (Arch)"; platform_script="$repo_root/tools/arch-setup.sh" ;;
                debian|ubuntu|linuxmint|pop|elementary|kali|zorin|raspbian) platform_label="Linux (Debian-based)"; platform_script="$repo_root/tools/debian-setup.sh" ;;
                fedora|rhel|centos|rocky|almalinux|ol|sles|opensuse*) platform_label="Linux (RPM-based)"; platform_script="$repo_root/tools/rpm-setup.sh" ;;
                *) platform_label="Linux (unknown distro)"; platform_script="$repo_root/tools/debian-setup.sh" ;;
            esac
        else
            platform_label="Linux/UNIX"
            platform_script="$repo_root/tools/debian-setup.sh"
        fi
        ;;
esac

# macOS brew/non-brew choice
if [ "$platform_label" = "macOS" ]; then
    default="Y"
    printf "Detected macOS. Run Homebrew setup (tools/macos-setup-brew.sh)? [Y/n]: "
    read -r reply
    reply=${reply:-$default}
    if [ "$reply" = "Y" ] || [ "$reply" = "y" ]; then
        "$repo_root/tools/macos-setup-brew.sh"
        exit $?
    fi
    printf "Run non-Homebrew setup (tools/macos-setup.sh)? [y/N]: "
    read -r reply
    if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
        "$repo_root/tools/macos-setup.sh"
        exit $?
    fi
    echo "Skipping macOS setup scripts."
    exit 0
fi

if [ -n "$platform_script" ] && [ -x "$platform_script" ]; then
    printf "Detected %s. Run %s? [y/N]: " "$platform_label" "$(basename "$platform_script")"
    read -r reply
    if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
        "$platform_script"
        exit $?
    fi
fi

# Windows/MSYS fallback: offer mingw-rpm if msys2 script not selected
if printf '%s\n' "$os_name" | grep -qE 'MINGW|MSYS'; then
    if [ -x "$repo_root/tools/mingw-rpm-setup.sh" ]; then
        printf "Run MinGW/RPM setup (tools/mingw-rpm-setup.sh)? [y/N]: "
        read -r reply
        if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
            "$repo_root/tools/mingw-rpm-setup.sh"
            exit $?
        fi
    fi
fi

echo "Setup-dev completed; no platform-specific setup script run."
