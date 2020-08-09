#
# win-setup - Prepare a Windows development environment for building Wireshark.
#
# Copyright 2015 Gerald Combs <gerald@wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

#requires -version 2

# Makefile.nmake + win-setup.sh does:
# - verify_tools: Checks required executables. CMake does this.
# - clean_setup: Removes current and past lib dirs.
# - process_libs: calls libverify or download for each lib.

# To do:
# - Make this the source of truth. Keep the list of libs here.
# - Download everything unconditionally, at least initially.

# Bugs:
# - Unzipping from the shell seems to be slower than Cygwin's unzip or 7zip.

<#
.SYNOPSIS
Prepare a Windows development environment for building Wireshark.

.DESCRIPTION
This script downloads and extracts third-party libraries required to compile
Wireshark.

.PARAMETER Destination
Specifies the destination directory for the text files. The path must
contain the pattern "wireshark-*-libs".

.PARAMETER Platform
Target platform. One of "win64" or "win32".

.INPUTS
-Destination Destination directory.
-Platform Target platform.

.OUTPUTS
A set of libraries required to compile Wireshark on Windows, along with
their compressed archives.
A date stamp (current-tag.txt)

.EXAMPLE
C:\PS> .\tools\win-setup.ps1 -Destination C:\wireshark-master-64-libs -Platform win64
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({$_ -like "*\wireshark-*-libs"})]
    [String]
    $Destination,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateSet("win32", "win64")]
    [String]
    $Platform
)

# Variables

# We create and delete files and directories. Bail out at the first sign of
# trouble instead of trying to catch exceptions everywhere.
$ErrorActionPreference = "Stop"

$Win64CurrentTag = "2020-08-09"
$Win32CurrentTag = "2020-08-09"

# Archive file / SHA256
$Win64Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "brotli-1.0.2-4-win64ws.zip" = "f60636764f0e2539ad86d37826e90445a346291f8d046bd4f5c998301f200195";
    "c-ares-1.15.0-win64ws.zip" = "3c4bfbbcbfe5e792660cb79769fc2a1996fa9938ec595247f611e7c59b1a62da";
    "gnutls-3.6.3-1-win64ws.zip" = "994ac2578e7b4ca01e589ab2598927d53f7370bc3ff679f3006b0e6bb7a06df4";
    "krb5-1.17-1-win64ws.zip" = "1f4a7ab86ae331ea9e58c9776a60def81ae9fe622882b2e8da2ad6ce6f6fb1d8";
    "libgcrypt-1.8.3-win64ws.zip" = "53b1c636cb89de308ca4ea01b4990cf1deca7f6c2446189c7ff6e971137ffd76";
    "libilbc-2.0.2-3-win64ws.zip" = "d7baeb98627c405bd7c3e41d6b07c4ea4f0f5db88436e566148320afd10cbb66";
    "libpcap-1.9.1-1-win64ws.zip" = "5713acad1b095b0351c3b05d7c8e51351af91ae19c306bb1aa985b69c5af7f16";
    "libsmi-svn-40773-win64ws.zip" = "571fcee71d741bf847c3247d4c2e1c42388ca6a9feebe08fc0d4ce053571d15d";
    "libssh-0.7.3-1-win64ws.zip" = "3a81b9f4a914a46f15243bbb13b6919ef1c20d4bf502c47646caeccff2cbd75c";
    "lua-5.2.4-unicode-win64-vc14.zip" = "e8968d2c7871ce1ea82cbd29ac1b3a2c59d3dec25e483c5e12de85df66f5d928";
    "lz4-1.8.3-win64ws.zip" = "2634ed7c132f50e8cf6dc25e9f1b6f2a3b3e4980b812cada7ef42b20fc1fba17";
    "MaxMindDB-1.3.2-win64ws.zip" = "9025c43e9b21ff0bfbaf206b8ed96e2920ef1434107f789e4c7c0c1d8b508952";
    "minizip-1.2.11-4-win64ws.zip" = "dd6bf24e2d946465ad19aa4f8c38e0db91da6585887935de68011982cd6fb2cb";
    "nghttp2-1.39.2-win64ws.zip" = "a53f4074bffd919539d90c8d0cde2ea6a10a383f14e38b706e7e70e55476e6bf";
    "sbc-1.3-1-win64ws.zip" = "08cef6898c421277a6582ef3225d8820f74a037cbd5b6e673a4d8f4593ce80a1";
    "snappy-1.1.3-1-win64ws.zip" = "692a15e70f2cdeca621988a46e936d3651e7feb5176981f2656a5e913c394bcc";
    "spandsp-0.0.6-1-win64ws.zip" = "0e46c61a5a8dca562c36e88a8962a50c1ec1a9fcf89dd05996dac5a79e454527";
    "vcpkg-export-20190318-win64ws.zip" = "72c2c43594b0581de2bc86517870a561cc40df294662502536b2a6c06cace87e";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "zstd-1.4.0-win64ws.zip" = "154199227bdfdfa608972bcdcea38e20768937085e5a59a8fa06c72d07b00d6b";
}

$Win32Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win32ws.zip" = "b785ec78dec6bca8252130eb884bfa28c1140001dd7369a535579176de9e4271";
    "brotli-1.0.2-4-win32ws.zip" = "193a9b35e42a73f77dabe2c99c57173d7f2bb215118c1cd027a6cf522cc3dc14";
    "c-ares-1.15.0-win32ws.zip" = "ddcdbdcc6c526496ed2083010fd913fb8a565ab726c86dfc57f30e65522f332d";
    "gnutls-3.6.3-1-win32ws.zip" = "42d8313ffb888f525d6c39330c39bcc2182e68ee8433a09dd85e1f1e1474f592";
    "krb5-1.17-1-win32ws.zip" = "f90cac08355ccfe624652d3e05f8e2e077b8830382315d4ea0a6fa52af08260b";
    "libgcrypt-1.8.3-win32ws.zip" = "409b72f2809019050cca91b9e670047c50a0752ff52999089178da54ef926393";
    "libilbc-2.0.2-3-win32ws.zip" = "b87967b5e46cd96d178bc3b3dbba5a75c069ef28ab8a86838c9d004690703997";
    "libpcap-1.9.1-1-win32ws.zip" = "431d8a6bac7a5e80ff8c7f1fc99388fb17c9555589b368577dc8c9d2f4499275";
    "libsmi-svn-40773-win32ws.zip" = "44bc81edfeb8948322ca365fc632e419383907c305cc922e6b74fdbb13827958";
    "libssh-0.7.3-1-win32ws.zip" = "b02f0d318175194ac538a24c9c9fc280a0ecad69fb3afd4945c106b4b7c4fa6f";
    "lua-5.2.4-unicode-win32-vc14.zip" = "ca2368a83f623674178e9441f71fb791e3c0b46f208e3dac28c6ac735f034bff";
    "lz4-1.8.3-win32ws.zip" = "6f77128f901d480ee0b82ab4fe5956e0f02fdcb2198d6d349e0b2fa1ac77c805";
    "MaxMindDB-1.3.2-win32ws.zip" = "5c8b4bf3092da8fad6edb005a5283c6a74b7e115a50da010953eed77d33c11b7";
    "minizip-1.2.11-4-win32ws.zip" = "41e113930902c2519c4644e8307a0cc51c5855e001e1e69768c48deb376142d0";
    "nghttp2-1.39.2-win32ws.zip" = "b511260befc210c1d6d0e920e5f5c47b9e6a21baee6e9874ef12a92093abd245";
    "sbc-1.3-1-win32ws.zip" = "ad37825e9ace4b849a5442c08f1ed7e30634e6b774bba4307fb86f35f82e71ba";
    "snappy-1.1.3-1-win32ws.zip" = "2508ef7c5d27655c356d7b86a00ac887fc178eab5df63595b8793953dae5c379";
    "spandsp-0.0.6-1-win32ws.zip" = "3c25f2f4d641d4257ec9922f6db77346a8eed2e360e7d0e27b828ade19c4705b";
    "vcpkg-export-20190318-win32ws.zip" = "5f9eb78b1ea9e6762c2a4104e0126f1f5453919dc9df66fef2b1e0be8d8c5829";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "zstd-1.4.0-win32ws.zip" = "9141716d4d749e67dad40d4aab6bbb3206085bf68e5acb03baf1e5667aa0b6f5";
}

# Subdirectory to extract an archive to
$ArchivesSubDirectory = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
}

# Plain file downloads

$Win32Files = @{
    "npcap-0.9996.exe" = "efd708a2109dbe27ccfb66c5d2726762646da3a1c0534274ada31863658fe162";
    "USBPcapSetup-1.5.4.0.exe" = "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622";
}

$Win64Files = @{
    "npcap-0.9996.exe" = "efd708a2109dbe27ccfb66c5d2726762646da3a1c0534274ada31863658fe162";
    "USBPcapSetup-1.5.4.0.exe" = "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622";
}

$Archives = $Win64Archives;
$Files = $Win64Files;
$CurrentTag = $Win64CurrentTag;

if ($Platform -eq "win32") {
    $Archives = $Win32Archives;
    $Files = $Win32Files;
    $CurrentTag = $Win32CurrentTag;
}

$CleanupItems = @(
    "bcg729-1.0.4-win??ws"
    "brotli-1.0.2-4-win??ws"
    "c-ares-1.9.1-1-win??ws"
    "c-ares-1.1*-win??ws"
    "gnutls-3.?.*-*-win??ws"
    "glib2-2.*-win??ws"
    "gtk2"
    "gtk3"
    "json-glib-1.0.2-*-win??ws"
    "kfw-3-2-2*"
    "krb5-*-win??ws"
    "libgcrypt-*-win??ws"
    "libilbc-2.0.2-3-win??ws"
    "libsmi-0.4.8"
    "libsmi-svn-40773-win??ws"
    "libssh-0.7.?-win??ws"
    "libxml2-*-win??ws"
    "lua5.1.4"
    "lua5.2.?"
    "lua5.2.?-win??"
    "lua-5.?.?-unicode-win??-vc??"
    "lz4-*-win??ws"
    "MaxMindDB-1.3.2-win??ws"
    "minizip-*-win??ws"
    "nghttp2-*-win??ws"
    "portaudio_v19"
    "portaudio_v19_2"
    "sbc-1.3-win??ws"
    "snappy-1.1.3-win??ws"
    "spandsp-0.0.6-win??ws"
    "upx301w"
    "upx303w"
    "user-guide"
    "vcpkg-export-*-win??ws"
    "zlib-1.2.5"
    "zlib-1.2.8"
    "zlib-1.2.*-ws"
    "zstd-*-win??ws"
    "AirPcap_Devpack_4_1_0_1622"
    "GeoIP-1.*-win??ws"
    "WinSparkle-0.3-44-g2c8d9d3-win??ws"
    "WinSparkle-0.5.?"
    "WpdPack"
    "current-tag.txt"
)

[Uri] $DownloadPrefix = "https://anonsvn.wireshark.org/wireshark-$($Platform)-libs/tags/$($CurrentTag)/packages"
$Global:SevenZip = "7-zip-not-found"
$proxy = $null

# Functions

# Verifies the contents of a file against a SHA256 checksum.
# Returns success (0) if the file exists and verifies.
# Returns error (1) if the file does not exist.
# Returns error (2) if the integrity check fails (an error is also printed).
function VerifyIntegrity($filename, $hash) {
    # Use absolute path because PS and .NET may have different working directories.
    $filepath = Convert-Path -Path $filename -ErrorAction SilentlyContinue
    if (-not ($filepath)) {
        return 1
    }
    # may throw due to permission error, I/O error, etc.
    try { $stream = [IO.File]::OpenRead($filepath) } catch { throw }

    try {
        $sha256 = New-Object Security.Cryptography.SHA256Managed
        $binaryHash = $sha256.ComputeHash([IO.Stream]$stream)
        $hexHash = ([System.BitConverter]::ToString($binaryHash) -Replace "-").ToLower()
        $hash = $hash.ToLower()
        if ($hexHash -ne $hash) {
            Write-Warning "$($filename): computed checksum $hexHash did NOT match $hash"
            return 2
        }
        return 0
    } finally {
        $stream.Close()
    }
}

# Downloads a file and checks its integrity. If a corrupt file already exists,
# it is removed and re-downloaded. Succeeds only if the SHA256 checksum matches.
function DownloadFile($fileName, $checksum, [Uri] $fileUrl = $null) {
    if ([string]::IsNullOrEmpty($fileUrl)) {
        $fileUrl = "$DownloadPrefix/$fileName"
    }
    $destinationFile = "$Destination\$fileName"
    if (Test-Path $destinationFile -PathType 'Leaf') {
        if ((VerifyIntegrity $destinationFile $checksum) -ne 0) {
            Write-Output "$fileName is corrupt, removing and retrying download."
            Remove-Item $destinationFile
        } else {
            Write-Output "$fileName already there; not retrieving."
            return
        }
    }

    if (-not ($Script:proxy)) {
        $Script:proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $Script:proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    }

    Write-Output "Downloading $fileUrl into $Destination"
    $webClient = New-Object System.Net.WebClient
    $webClient.proxy = $Script:proxy
    $webClient.DownloadFile($fileUrl, "$destinationFile")
    Write-Output "Verifying $destinationFile"
    if ((VerifyIntegrity $destinationFile $checksum) -ne 0) {
        Write-Output "Download is corrupted, aborting!"
        exit 1
    }
}

# Find 7-Zip, downloading it if necessary.
# If we ever add NuGet support we might be able to use
# https://github.com/thoemmi/7Zip4Powershell
function Bootstrap7Zip() {
    $searchExes = @("7z.exe", "7za.exe")
    $binDir = "$Destination\bin"

    # First, check $env:Path.
    foreach ($exe in $searchExes) {
        if (Get-Command $exe -ErrorAction SilentlyContinue)  {
            $Global:SevenZip = "$exe"
            Write-Output "Found 7-zip on the path"
            return
        }
    }

    # Next, look in a few likely places.
    $searchDirs = @(
        "${env:ProgramFiles}\7-Zip"
        "${env:ProgramFiles(x86)}\7-Zip"
        "${env:ProgramW6432}\7-Zip"
        "${env:ChocolateyInstall}\bin"
        "${env:ChocolateyInstall}\tools"
        "$binDir"
    )

    foreach ($dir in $searchDirs) {
        if ($dir -ne $null -and (Test-Path $dir -PathType 'Container')) {
            foreach ($exe in $searchExes) {
                if (Test-Path "$dir\$exe" -PathType 'Leaf') {
                    $Global:SevenZip = "$dir\$exe"
                    Write-Output "Found 7-zip at $dir\$exe"
                    return
                }
            }
        }
    }

    # Finally, download a copy from anonsvn.
    if ( -not (Test-Path $binDir -PathType 'Container') ) {
        New-Item -ItemType 'Container' "$binDir" > $null
    }

    Write-Output "Unable to find 7-zip, retrieving from anonsvn into $binDir\7za.exe"
    [Uri] $bbUrl = "https://anonsvn.wireshark.org/wireshark-win32-libs/trunk/bin/7za.exe"
    $checksum = "77613cca716edf68b9d5bab951463ed7fade5bc0ec465b36190a76299c50f117"
    DownloadFile "bin\7za.exe" "$checksum" "$bbUrl"

    $Global:SevenZip = "$binDir\7za.exe"
}

function DownloadArchive($fileName, $checksum, $subDir) {
    DownloadFile $fileName $checksum
    # $shell = New-Object -com shell.application
    $archiveFile = "$Destination\$fileName"
    $archiveDir = "$Destination\$subDir"
    if ($subDir -and -not (Test-Path $archiveDir -PathType 'Container')) {
        New-Item -ItemType Directory -Path $archiveDir > $null
    }
    if (Test-Path 'env:WIRESHARK_DO_NOT_USE_7ZIP') {
        # Display a progress bar while extracting and overwriting existing files.
        Expand-Archive $archiveFile $archiveDir -Force -ErrorVariable $expandError
        if ($expandError) {
            exit 1
        }
        return
    }

    $activity = "Extracting into $($archiveDir)"
    Write-Progress -Activity "$activity" -Status "Running 7z x $archiveFile ..."
    & "$SevenZip" x "-o$archiveDir" -y "$archiveFile" 2>&1 |
        Set-Variable -Name SevenZOut
    $bbStatus = $LASTEXITCODE
    Write-Progress -Activity "$activity" -Status "Done" -Completed
    if ($bbStatus -gt 0) {
        Write-Output $SevenZOut
        exit 1
    }
}

# On with the show

# Make sure $Destination exists and do our work there.
if ( -not (Test-Path $Destination -PathType 'Container') ) {
    New-Item -ItemType 'Container' "$Destination" > $null
}

# CMake's file TO_NATIVE_PATH passive-aggressively omits the drive letter.
Set-Location "$Destination"
$Destination = $(Get-Item -Path ".\")
Write-Output "Working in $Destination"

# Check our last known state
$destinationTag = "INVALID"
$tagFile = "current_tag.txt"
if ((Test-Path $tagFile -PathType 'Leaf') -and -not ($Force)) {
    $destinationTag = Get-Content $tagFile
}

if ($destinationTag -ne $CurrentTag) {
    Write-Output "Tag $CurrentTag not found. Refreshing."
    Bootstrap7Zip
    $activity = "Removing directories"
    foreach ($oldItem in $CleanupItems) {
        if (Test-Path $oldItem) {
            Write-Progress -Activity "$activity" -Status "Removing $oldItem"
            Remove-Item -force -recurse $oldItem
        }
    }
    Write-Progress -Activity "$activity" -Status "Done" -Completed
} else {
    Write-Output "Tag $CurrentTag found. Skipping."
    exit 0
}

# Download files
foreach ($item in $Files.GetEnumerator() | Sort-Object -property key) {
    DownloadFile $item.Name $item.Value
}

# Download and extract archives
foreach ($item in $Archives.GetEnumerator() | Sort-Object -property key) {
    $subDir = $ArchivesSubDirectory[$item.Name]
    DownloadArchive $item.Name $item.Value $subDir
}

# Save our last known state
Set-Content -Path $tagFile -Value "$CurrentTag"
