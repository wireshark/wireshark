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

# To do:
# - Use Expand-Archive instead of `cmake -E tar`? That requires PS >= 5.0

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
Target platform. Must be one of "win64" or "arm64".

.PARAMETER CMakeExecutable
Specifies the path to the CMake executable, which is used to extract archives.

.INPUTS
-Destination Destination directory.
-Platform Target platform.
-CMakeExecutable Path to CMake.

.OUTPUTS
A set of libraries required to compile Wireshark on Windows, along with
their compressed archives.
A manifest file (library-manifest.xml)

.EXAMPLE
C:\PS> .\tools\win-setup.ps1 -Destination C:\wireshark-master-64-libs -Platform x64
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({$_ -like "*[/\]wireshark-*-libs"})]
    [String]
    $Destination,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateSet("x64", "arm64")]
    [String]
    $Platform,

    [Parameter(Mandatory=$false, Position=3)]
    [ValidateScript({$_ | Test-Path -Type leaf })]
    [String]
    $CMakeExecutable = "CMake"
)

# Variables

# We create and delete files and directories. Bail out at the first sign of
# trouble instead of trying to catch exceptions everywhere.
$ErrorActionPreference = "Stop"

# Archive file / SHA256
$X64Archives = @{
    "AirPcap/AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729/bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "brotli/brotli-1.0.9-1-win64ws.zip" = "3f8d24aec8668201994327ff8d8542fe507d1d468a500a1aec50d0415f695aab";
    "c-ares/c-ares-1.19.1-1-x64-windows-ws.zip" = "cecd95f125a34b6f1d5dfc9586792077cb70820764ffc10d43b0617c1861ae85";
    "gnutls/gnutls-3.8.3-1-x64-mingw-dynamic-ws.zip" = "0d8f99029319e1967fd916586eecfd776a9b564614468b233b6eda8bc23ca20d";
    "krb5/krb5-1.20.1-1-x64-windows-ws.zip" = "a1e5c582afce6e2f72f0f5bd66df2c0f3cc984532a1da5314fc89d7b7f29cdbf";
    "libgcrypt/libgcrypt-1.10.2-2-x64-mingw-dynamic-ws.zip" = "477cfce91d791b34df75a5ad83626f1ac2ee147eff7965e52266a4fc3da0f920";
    "libilbc/libilbc-2.0.2-4-x64-windows-ws.zip" = "4f35a1ffa03c89bf473f38249282a7867b203988d2b6d3d2f0924764619fd5f5";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64ws.zip" = "ee89944a19ab6e1c873bdecb9fc6205d317c41e6da6ec1d30bc892fddfd143da";
    "libpcap/libpcap-1.10.4-1-x64-windows-ws.zip" = "ad18ee1da72ce9df524b8baf9c185f237e534ef8e356c0b3eb3a5d6762004656";
    "libsmi/libsmi-2021-01-15-2-x64-windows-ws.zip" = "ee8e349427d2a4ee9c18fc6b5839bd6df41685ecba03506179c21425e04f3413";
    "libssh/libssh-0.10.6plus-1-x64-mingw-dynamic-ws.zip" = "b4debbc7b5ec34dd998cdc17699526191219e0c593d9797a4bd6147eab020934";
    "lua/lua-5.2.4-unicode-win64-vc14.zip" = "e8968d2c7871ce1ea82cbd29ac1b3a2c59d3dec25e483c5e12de85df66f5d928";
    "lz4/lz4-1.9.3-1-win64ws.zip" = "7129515893ffdc439f4ffe9673c4bc43f9042e910bb2607e68dde6b99a1ab058";
    "minizip/minizip-1.3-1-x64-windows-ws.zip" = "eb0bb5fffda5328e192d0d7951ff0254e64dcd736d46909fde7db792c1c53bcc";
    "nghttp2/nghttp2-1.57.0-1-x64-windows-ws.zip" = "94afb12d63d0830dc25e5605c30a6a91fe1f7284c1e6ddfff177d961d5b52bbd";
    "nghttp3/nghttp3-1.0.0-1-x64-windows-ws.zip" = "219a0024b79627c00fa1c134085678edbfac72b7b5eaf45db84f36e2553e1638";
    "opus/opus-1.3.1-3-win64ws.zip" = "1f7a55a6d2d7215dffa4a43bca8ca05024bd4ba1ac3d0d0c405fd38b09cc2205";
    "sbc/sbc-2.0-1-x64-windows-ws.zip" = "d1a58f977dcffa168b11b280bd10228191582d263b7c901e50cde7c1c43d9c04";
    "snappy/snappy-1.1.9-1-win64ws.zip" = "fa907724be019bcc55d27ebe88257ba8898b5c38b719099b8164ac78600d81cc";
    "spandsp/spandsp-0.0.6-5-x64-windows-ws.zip" = "cbb18310876ec6f081662253a2d37f5174ac60c58b0b7cd6759852fbcfaa7d7f";
    "speexdsp/speexdsp-1.21.1-1-win64ws.zip" = "d36db62e64ffaee38d9f607bef07d3778d8957ad29757f3eba169eb135f1a4e5";
    "vcpkg-export/vcpkg-export-20231017-1-x64-windows-ws.zip" = "fc5ea8110ce5e905e3342197481a805b6c2c87e273b0370bcc6a5964316c20ee";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zstd/zstd-1.5.2-1-win64ws.zip" = "d920afe636951cfcf144824d9c075d1f2c13387f4739152fe185fd9c09fc58f2";
}

$Arm64Archives = @{
    "bcg729/bcg729-1.1.1-1-win64armws.zip" = "f4d76b9acf0d0e12e87a020e9805d136a0e8775e061eeec23910a10828153625";
    "brotli/brotli-1.0.9-1-win64armws.zip" = "5ba1b62ebc514d55c3eae85a00ff107e587b6e7cb1275e2d33fcddcd49f8e2af";
    "c-ares/c-ares-1.19.1-1-arm64-windows-ws.zip" = "ec13f3ca07c1916872d08d3abaec3eaeac266dc2befdbc15d5a1317f2a1dbe3c";
    "gnutls/gnutls-3.8.3-1-arm64-mingw-dynamic-ws.zip" = "b9f0ee9cfe5012241aa5b9832212ea31408edf9bfc968762a2cfb091202fcc4b";
    "krb5/krb5-1.20.1-1-arm64-windows-ws.zip" = "6afe3185ea7621224544683a89d7c724d32bef6f1b552738dbc713ceb2151437";
    "libgcrypt/libgcrypt-1.10.2-2-arm64-mingw-dynamic-ws.zip" = "cd42fa2739a204e129d655e1b0dda83ceb27399812b8b2eccddae4a9ecd8d0ce";
    "libilbc/libilbc-2.0.2-4-arm64-windows-ws.zip" = "00a506cc1aac8a2e31856e463a555d899b5a6ccf376485a124104858ccf0be6d";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64armws.zip" = "9996327f301cb4a4de797bc024ad0471acd95c1850a2afc849c57fcc93360610";
    "libpcap/libpcap-1.10.4-1-arm64-windows-ws.zip" = "98dbac265e3617eb0ab1a690902a4989e022d0761098c2753bff4cd0189419b3";
    "libsmi/libsmi-2021-01-15-2-arm64-windows-ws.zip" = "3f5b7507a19436bd6494e2cbc89856a5980950f931f7cf0d637a8e764914d015";
    "libssh/libssh-0.10.6plus-1-arm64-mingw-dynamic-ws.zip" = "2de3a300b0fbb7593c863aa8f302f801a2a1041ced8dfa8d65b7e7b42008c7ef";
    "lua/lua-5.2.4-unicode-arm64-windows-vc17.zip" = "5848e23352e35b69f4cdabaca3754c2c5fb11e5461bb92b71e059e558e4b2d12";
    "lz4/lz4-1.9.4-1-win64armws.zip" = "59a3ed3f9161be7614a89afd2ca21c43f26dd916afd4aa7bfdc4b148fb10d485";
    "minizip/minizip-1.3-1-arm64-windows-ws.zip" = "e5b35d064ff10f1ab1ee9193a0965fd1eb3d1e16eab5a905ab3fea9b14fb5afe";
    "nghttp2/nghttp2-1.57.0-1-arm64-windows-ws.zip" = "3f264dc0ccb48850e07ec136dede5b0ad0e39e31ff2d2e6ab215348ce2d9e570";
    "nghttp3/nghttp3-1.0.0-1-arm64-windows-ws.zip" = "cf53090b514d3193d75b81562235ae1e7a8a9d462e37f515f9a9a29c6b469236";
    "opus/opus-1.4-1-win64armws.zip" = "51d10381360d5691b2022dde5b284266d9b0ce9a3c9bd7e86f9a4ff1a4f7d904";
    "sbc/sbc-2.0-1-arm64-windows-ws.zip" = "83cfe4a8b6fa5bae253ecacc1c02e6e4c61b4ad9ad0e5e63f0f30422fb6eac96";
    "snappy/snappy-1.1.9-1-win64armws.zip" = "f3f6ec841024d18df06934ff70f44068a4e8f1008eca1f363257645647f74d4a";
    "spandsp/spandsp-0.0.6-5-arm64-windows-ws.zip" = "fdf01e3c33e739ff9399b7d42cd8230c97cb27ce51865a0f06285a8f68206b6c";
    "speexdsp/speexdsp-1.2.1-1-win64armws.zip" = "1759a9193065f27e50dd79dbb1786d24031ac43ccc48c40dca46d8a48552e3bb";
    "vcpkg-export/vcpkg-export-20231017-1-arm64-windows-ws.zip" = "2752e2e059ea13e8b4e1ef5f8892b81b745da6838e513bd6e4e548d290d9f472";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zstd/zstd-1.5.5-1-win64armws.zip" = "0e448875380cc5d5f5539d994062201bfa564e4a27466bc3fdfec84d9008e51d";
}

# Subdirectory to extract an archive to
$ArchivesSubDirectory = @{
    "AirPcap/AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
}

# Plain file downloads

$X64Files = @{
    # Nothing here
}

$Arm64Files = @{
    # Nothing here
}

$Archives = $X64Archives;
$Files = $X64Files;

if ($Platform -eq "arm64") {
    $Archives = $Arm64Archives;
    $Files = $Arm64Files;
}

$CurrentManifest = $Archives + $Files

$CleanupItems = @(
    "bcg729-1.0.4-win??ws"
    "brotli-1.0.*-win??ws"
    "c-ares-1.9.1-1-win??ws"
    "c-ares-1.1*-win??ws"
    "gnutls-3.?.*-*-win??ws"
    "krb5-*-win??ws"
    "libgcrypt-*-win??ws"
    "libilbc-2.0.2-3-win??ws"
    "libmaxminddb-1.4.3-1-win??ws"
    "libpcap-1.9.1-1-win??ws"
    "libsmi-0.4.8"
    "libsmi-svn-40773-win??ws"
    "libssh-0.*-win??ws"
    "libxml2-*-win??ws"
    "lua5.1.4"
    "lua5.2.?"
    "lua5.2.?-win??"
    "lua-5.?.?-unicode-win??-vc??"
    "lz4-*-win??ws"
    "MaxMindDB-1.3.2-win??ws"
    "minizip-*-win??ws"
    "nghttp2-*-win??ws"
    "opus-1.3.1-?-win??ws"
    "pcre2-*-win??ws"
    "sbc-1.3-win??ws"
    "snappy-1.1.*-win??ws"
    "spandsp-0.0.6-win??ws"
    "speexdsp-*-win??ws"
    "user-guide"
    "vcpkg-export-*-win??ws"
    "zstd-*-win??ws"
    "AirPcap_Devpack_4_1_0_1622"
    "WinSparkle-0.3-44-g2c8d9d3-win??ws"
    "WinSparkle-0.5.?"
    "current-tag.txt"
    "library-manifest.xml"
)

# The dev-libs site repository is at
# https://gitlab.com/wireshark/wireshark-development-libraries
[Uri] $DownloadPrefix = "https://dev-libs.wireshark.org/windows/packages"
$proxy = $null

# Functions

# Verifies the contents of a file against a SHA256 hash.
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
            Write-Warning "$($filename): computed file hash $hexHash did NOT match $hash"
            return 2
        }
        return 0
    } finally {
        $stream.Close()
    }
}

# Downloads a file and checks its integrity. If a corrupt file already exists,
# it is removed and re-downloaded. Succeeds only if the SHA256 hash matches.
function DownloadFile($fileName, $fileHash, [Uri] $fileUrl = $null) {
    if ([string]::IsNullOrEmpty($fileUrl)) {
        $fileUrl = "$DownloadPrefix/$fileName"
    }
    $destinationFile = "$Destination\" + [string](Split-Path -Leaf $fileName)
    if (Test-Path $destinationFile -PathType 'Leaf') {
        if ((VerifyIntegrity $destinationFile $fileHash) -ne 0) {
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
    if ((VerifyIntegrity $destinationFile $fileHash) -ne 0) {
        Write-Output "Download is corrupted, aborting!"
        exit 1
    }
}

function DownloadArchive($fileName, $fileHash, $subDir) {
    DownloadFile $fileName $fileHash
    $archiveFile = "$Destination\" + [string](Split-Path -Leaf $fileName)
    $archiveDir = "$Destination\$subDir"
    if ($subDir -and -not (Test-Path $archiveDir -PathType 'Container')) {
        New-Item -ItemType Directory -Path $archiveDir > $null
    }

    $activity = "Extracting into $($archiveDir)"
    Write-Progress -Activity "$activity" -Status "Extracting $archiveFile using CMake ..."
    Push-Location "$archiveDir"
    & "$CMakeExecutable" -E tar xf "$archiveFile" 2>&1 | Set-Variable -Name CMakeOut
    $cmStatus = $LASTEXITCODE
    Pop-Location
    Write-Progress -Activity "$activity" -Status "Done" -Completed
    if ($cmStatus -gt 0) {
        Write-Output $CMakeOut
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
$destinationManifest = @{ "INVALID" = "INVALID" }
$manifestFile = "library-manifest.xml"
if ((Test-Path $manifestFile -PathType 'Leaf') -and -not ($Force)) {
    $destinationManifest = Import-Clixml $manifestFile
}

function ManifestList($manifestHash) {
    $manifestHash.keys | Sort | ForEach-Object { "$_ : $($manifestHash[$_])" }
}

if (Compare-Object -ReferenceObject (ManifestList($destinationManifest)) -DifferenceObject (ManifestList($CurrentManifest))) {
    Write-Output "Current library manifest not found. Refreshing."
    $activity = "Removing directories"
    foreach ($oldItem in $CleanupItems) {
        if (Test-Path $oldItem) {
            Write-Progress -Activity "$activity" -Status "Removing $oldItem"
            Remove-Item -force -recurse $oldItem
        }
    }
    Write-Progress -Activity "$activity" -Status "Done" -Completed
} else {
    Write-Output "Current library manifest found. Skipping download."
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
$CurrentManifest | Export-Clixml -Path $manifestFile -Encoding utf8
