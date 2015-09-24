#
# Get-HardenFlags - Checks hardening flags on the binaries.
#
# Copyright 2015 Graham Bloice <graham.bloice@trihedral.com>
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

# Get-HardenFlags does:
#   call the dumpbin utility to get the binary header flags
#   on all the binaries in the distribution, and then filters
#   for the NXCOMPAT and DYNAMICBASE flags.

<#
.SYNOPSIS
Checks the NXCOMPAT and DYNAMICBASE flags on all the binaries.

.DESCRIPTION
This script downloads and extracts third-party libraries required to compile
Wireshark.

.PARAMETER BinaryDir
Specifies the directory where the binaries may be found.

.INPUTS
-BinaryDir Directory containing the binaries to be checked.

.OUTPUTS
Any binary that doesn't have the flags is written to the error stream

.EXAMPLE
C:\PS> .\tools\Get-HardenFlags.ps1 -BinaryDir run\RelWithDebInfo
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [String]
    $BinaryDir
)

# CD into the bindir, allows Resolve-Path to work in relative mode.
Push-Location $BinDir

# Retrieve the list of binaries.  -Filter is quicker than -Include, but can only handle one item
$Binaries = Get-ChildItem -Path $BinaryDir -Recurse -Include *.exe,*.dll

# Number of "soft" binaries found
$Count = 0;

# Iterate over the list
$Binaries | ForEach-Object {

    # Get the flags
    $flags = dumpbin $_ /HEADERS;

    # Check for the required flags
    $match = $flags | Select-String -Pattern "NX compatible", "Dynamic base"
    if ($match.Count -ne 2) {

        # Write-Error outputs error records, we simply want the filename
        [Console]::Error.WriteLine((Resolve-Path $_ -Relative))

        $Count++
    }
}

exit $Count