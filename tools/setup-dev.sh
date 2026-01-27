#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Configure local git template/hooks for Wireshark development.

set -e

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Print final summary with available setup scripts
print_completion_summary() {
    echo ""
    echo "----------------------------------------------"
    echo "  All Done"
    echo "----------------------------------------------"
    echo ""
    echo "Git configuration is complete."
    echo "You can install dependencies later by running the appropriate script:"
    echo "  - macOS:   tools/macos-setup-brew.sh or tools/macos-setup.sh"
    echo "  - Debian:  tools/debian-setup.sh"
    echo "  - Fedora:  tools/rpm-setup.sh"
    echo "  - Arch:    tools/arch-setup.sh"
    echo "  - MSYS2 (Windows):   tools/msys2-setup.sh"
    echo "  - MinGW (Windows):   tools/mingw-rpm-setup.sh"
    echo ""
}

echo ""
echo "=============================================="
echo "   Wireshark Development Environment Setup"
echo "=============================================="
echo ""

echo "[1/3] Configuring commit message template..."
echo "      Template: .gitmessage"
git config commit.template ".gitmessage"
echo "      Done."
echo ""

echo "[2/3] Configuring Git hooks for code quality checks..."
echo "      Hooks path: tools/git_hooks"
git config core.hooksPath "tools/git_hooks"
echo "      Done."
echo ""

echo "[3/3] Verifying Git user identity..."
name="$(git config user.name || true)"
email="$(git config user.email || true)"

if [ -z "$name" ] || [ -z "$email" ]; then
    cat <<'EOF'

----------------------------------------------
  WARNING: Git identity not configured
----------------------------------------------

Your Git user.name or user.email is not set.
Commits require a valid identity to be attributed correctly.

To configure your identity, run:

  git config --global user.name "Your Name"
  git config --global user.email "you@example.com"

If you have already made commits, update the author with:

  git commit --amend --reset-author --no-edit

EOF
    exit 1
else
    echo "      Identity: $name <$email>"
fi

echo ""
echo "----------------------------------------------"
echo "  Git Configuration Complete"
echo "----------------------------------------------"
echo ""
echo "Your development environment is now configured with:"
echo "  - Commit template for consistent commit messages"
echo "  - Git hooks for pre-commit validation"
echo ""

# Ask if user wants to continue with platform setup
printf "Would you like to install platform-specific build dependencies? [y/N]: "
read -r continue_reply
if [ "$continue_reply" != "y" ] && [ "$continue_reply" != "Y" ]; then
    print_completion_summary
    exit 0
fi

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
    echo ""
    echo "----------------------------------------------"
    echo "  Platform Detected: macOS"
    echo "----------------------------------------------"
    echo ""
    echo "Choose your preferred package manager:"
    echo ""
    printf "  Option 1: Homebrew setup (tools/macos-setup-brew.sh)? [y/N]: "
    read -r reply
    if [ "$reply" = "Y" ] || [ "$reply" = "y" ]; then
        echo ""
        echo "Running Homebrew setup..."
        "$repo_root/tools/macos-setup-brew.sh"
        exit $?
    fi
    printf "  Option 2: Non-Homebrew setup (tools/macos-setup.sh)? [y/N]: "
    read -r reply
    if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
        echo ""
        echo "Running non-Homebrew setup..."
        "$repo_root/tools/macos-setup.sh"
        exit $?
    fi
    echo ""
    echo "Skipping macOS dependency installation."
    echo "You can run the setup scripts manually later if needed."
    exit 0
fi

if [ -n "$platform_script" ] && [ -x "$platform_script" ]; then
    echo ""
    echo "----------------------------------------------"
    echo "  Platform Detected: $platform_label"
    echo "----------------------------------------------"
    echo ""
    printf "Run $(basename "$platform_script") to install dependencies? [y/N]: "
    read -r reply
    if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
        echo ""
        echo "Running platform setup..."
        "$platform_script"
        exit $?
    fi
fi

# Windows/MSYS fallback: offer mingw-rpm if msys2 script not selected
if printf '%s\n' "$os_name" | grep -qE 'MINGW|MSYS'; then
    if [ -x "$repo_root/tools/mingw-rpm-setup.sh" ]; then
        echo ""
        echo "Alternative: MinGW/RPM environment setup available."
        printf "  Run mingw-rpm-setup.sh? [y/N]: "
        read -r reply
        if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
            echo ""
            echo "Running MinGW/RPM setup..."
            "$repo_root/tools/mingw-rpm-setup.sh"
            exit $?
        fi
    fi
fi

print_completion_summary
