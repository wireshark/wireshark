# SPDX-License-Identifier: GPL-2.0-or-later

$ErrorActionPreference = "Stop"

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "Could not determine repository root. Are you in a git repo?" -ForegroundColor Red
    exit 1
}

Write-Host "Setting commit template to .gitmessage"
git config commit.template "$repoRoot/.gitmessage"

Write-Host "Setting hooks path to tools/git_hooks"
git config core.hooksPath "$repoRoot/tools/git_hooks"

$name = git config user.name 2>$null
$email = git config user.email 2>$null

if (-not $name -or -not $email) {
    Write-Host ""
    Write-Host "Git user.name or user.email is not set."
    Write-Host "To configure your name and email for git, run:" -ForegroundColor Yellow
    Write-Host '  git config --global user.name "Your Name"'
    Write-Host '  git config --global user.email you@example.com'
    Write-Host ""
    Write-Host "After that update the author of your latest commit with:" -ForegroundColor Yellow
    Write-Host '  git commit --amend --reset-author --no-edit'
    exit 1
} else {
    Write-Host "Git user configured as: $name <$email>"
}

Write-Host "Done. Hooks and commit template are configured for this repository."
Write-Host "For Windows-specific setup instructions, see:"
Write-Host "  https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows.html"
