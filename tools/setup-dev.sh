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
    echo "Git user.name or user.email is not set. Please run:"
    echo "  git config --global user.name \"Your Name\""
    echo "  git config --global user.email you@example.com"
else
    echo "Git user configured as: $name <$email>"
fi

echo "Done. Hooks and commit template are configured for this repository."
