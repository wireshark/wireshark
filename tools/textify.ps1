#
# Textify - Copy text files and make them useful for Windows users.
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
        $contents = Get-Content $src_file
        [System.IO.File]::WriteAllLines($dst_file, $contents, $no_bom_encoding)
        Write-Host "Textified $src_file to $dst_file"
    } else {
        Write-Host "Skipping $src_file"
    }
}
