# SPDX-License-Identifier: GPL-2.0-or-later

$ErrorActionPreference = "Stop"

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host ""
    Write-Host "ERROR: Could not determine repository root." -ForegroundColor Red
    Write-Host "Please make sure you are running this script from within a Git repository." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   Wireshark Development Environment Setup" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Configuring commit message template..." -ForegroundColor White
Write-Host "      Template: .gitmessage" -ForegroundColor Gray
git config commit.template "$repoRoot/.gitmessage"
Write-Host "      Done." -ForegroundColor Green
Write-Host ""

Write-Host "[2/3] Configuring Git hooks for code quality checks..." -ForegroundColor White
Write-Host "      Hooks path: tools/git_hooks" -ForegroundColor Gray
git config core.hooksPath "$repoRoot/tools/git_hooks"
Write-Host "      Done." -ForegroundColor Green
Write-Host ""

Write-Host "[3/3] Verifying Git user identity..." -ForegroundColor White
$name = git config user.name 2>$null
$email = git config user.email 2>$null

if (-not $name -or -not $email) {
    Write-Host ""
    Write-Host "----------------------------------------------" -ForegroundColor Yellow
    Write-Host "  WARNING: Git identity not configured" -ForegroundColor Yellow
    Write-Host "----------------------------------------------" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Your Git user.name or user.email is not set."
    Write-Host "Commits require a valid identity to be attributed correctly."
    Write-Host ""
    Write-Host "To configure your identity, run:" -ForegroundColor White
    Write-Host '  git config --global user.name "Your Name"' -ForegroundColor Gray
    Write-Host '  git config --global user.email "you@example.com"' -ForegroundColor Gray
    Write-Host ""
    Write-Host "If you have already made commits, update the author with:" -ForegroundColor White
    Write-Host '  git commit --amend --reset-author --no-edit' -ForegroundColor Gray
    Write-Host ""
    exit 1
} else {
    Write-Host "      Identity: $name <$email>" -ForegroundColor Green
}

Write-Host ""
Write-Host "----------------------------------------------" -ForegroundColor Green
Write-Host "  Setup Complete" -ForegroundColor Green
Write-Host "----------------------------------------------" -ForegroundColor Green
Write-Host ""
Write-Host "Your development environment is now configured with:"
Write-Host "  - Commit template for consistent commit messages" -ForegroundColor Gray
Write-Host "  - Git hooks for pre-commit validation" -ForegroundColor Gray
Write-Host ""
Write-Host "For Windows-specific build setup instructions, see:" -ForegroundColor White
Write-Host "  https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows.html" -ForegroundColor Cyan
Write-Host ""
