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

# This script will probably fail for the forseeable future.
#
# Many of our third-party libraries are compiled using MinGW-w64. Its version
# of `ld` doesn't enable the dynamicbase, nxcompat, or high-entropy-va flags
# by default. When you *do* pass --dynamicbase it strips the relocation
# section of the executable:
#
#   https://sourceware.org/bugzilla/show_bug.cgi?id=19011
#
# As a result, none of the distributions that produce Windows applications
# and libraries have any sort of hardening flags enabled:
#
#   http://mingw-w64.org/doku.php/download
#

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

# Create a list of 3rd party binaries that are not hardened
$SoftBins = (
    "libpixmap.dll",
    "libwimp.dll",
    "libgail.dll",
    "airpcap.dll",
    "comerr32.dll",
    "k5sprt32.dll",
    "krb5_32.dll",
    "libatk-1.0-0.dll",
    "libcairo-2.dll",
    "libffi-6.dll",
    "libfontconfig-1.dll",
    "libfreetype-6.dll",
    "libgcc_s_sjlj-1.dll",
    "libgcrypt-20.dll",
    "libgdk-win32-2.0-0.dll",
    "libgdk_pixbuf-2.0-0.dll",
    "libGeoIP-1.dll",
    "libgio-2.0-0.dll",
    "libglib-2.0-0.dll",
    "libgmodule-2.0-0.dll",
    "libgmp-10.dll",
    "libgnutls-28.dll",
    "libgobject-2.0-0.dll",
    "libgpg-error-0.dll",
    "libgtk-win32-2.0-0.dll",
    "libharfbuzz-0.dll",
    "libhogweed-2-4.dll",
    "libintl-8.dll",
    "libjasper-1.dll",
    "libjpeg-8.dll",
    "liblzma-5.dll",
    "libnettle-4-6.dll",
    "libp11-kit-0.dll",
    "libpango-1.0-0.dll",
    "libpangocairo-1.0-0.dll",
    "libpangoft2-1.0-0.dll",
    "libpangowin32-1.0-0.dll",
    "libpixman-1-0.dll",
    "libpng15-15.dll",
    "libtasn1-6.dll",
    "libtiff-5.dll",
    "libxml2-2.dll",
# The x64 ones that are different
    "comerr64.dll",
    "k5sprt64.dll",
    "krb5_64.dll",
    "libgcc_s_seh-1.dll",
    "libgpg-error6-0.dll",
    "libpng16-16.dll",
# Unfortunately the nsis uninstaller is not hardened.
    "uninstall.exe"
)

# CD into the bindir, allows Resolve-Path to work in relative mode.
Push-Location $BinaryDir
[Console]::Error.WriteLine("Checking in $BinaryDir for unhardened binaries:")

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

        # Don't count files that won't ever be OK
        if ($SoftBins -notcontains (Split-Path $_ -Leaf)) {
            $Count++
        }
    }
}

exit $Count
