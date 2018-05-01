#
# Textify - Copy text files and make them useful for Windows users.
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

#requires -version 2

<#
.SYNOPSIS
Text file conversion script for packaging on Windows.

.DESCRIPTION
This script copies a text file from a source to a destination,
converting line endings and adding a ".txt" filename extension
if needed. If the destination is a directory the source file
name is used. Newer files will not be overwritten.

The destination file should be double-clickable and usable
when Notepad is the default editor.

.PARAMETER Destination
Specifies the destination directory for the text files.

.PARAMETER SourceFiles
The names of the files to copy and convert.

.INPUTS
-Destination Destination directory.
-SourceFiles List of files.

.OUTPUTS
Copies of input files, UTF8 encoded with Windows line endings and no BOM in the
destination directory.

.EXAMPLE
C:\PS> .\tools\textify.ps1 -Destination wireshark-release-staging COPYING
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_ -PathType 'Container'})]
    [String]
    $Destination,

    [Parameter(Mandatory=$true, Position=1, ValueFromRemainingArguments=$true)]
    [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
    [String[]]
    $SourceFiles
)

$no_bom_encoding = New-Object System.Text.UTF8Encoding($False)

foreach ($src_file in Get-ChildItem $SourceFiles) {
    if ($Destination) {
        $base = Split-Path -Leaf $src_file
        $dst_file = Join-Path $Destination $base
    } else {
        $dst_file = $src_file.FullName
    }

    if (-not $dst_file.EndsWith(".txt")) {
        $dst_file += ".txt"
    }

    $src_modtime = (Get-Item $src_file).LastWriteTime

    if (-not (Test-Path $dst_file) -or ((Get-Item $dst_file).LastWriteTime -lt $src_modtime)) {
        # "Get-Content -Encoding" is undocumented in PS 2.0, but works
        # here. If it doesn't work elsewhere we can use:
        # $contents = [System.IO.File]::ReadAllLines($src_file, $no_bom_encoding)
        $contents = Get-Content -Encoding UTF8 $src_file
        # We might want to write this out with a BOM in order to improve
        # the chances of Notepad's UTF-8 heuristics.
        # https://blogs.msdn.microsoft.com/oldnewthing/20070417-00/?p=27223
        [System.IO.File]::WriteAllLines($dst_file, $contents, $no_bom_encoding)
        Write-Host "Textified $src_file to $dst_file"
    } else {
        Write-Host "Skipping $src_file"
    }
}
