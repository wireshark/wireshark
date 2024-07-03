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
    "c-ares/c-ares-1.28.1-1-x64-windows-ws.zip" = "6509df8e15ed67e87fac84a3b0acaa7b804b59f272fdf9decfb6157d241e73da";
    "falcosecurity-libs/falcosecurity-libs-0.17.1-1-x64-ws.zip" = "371278147543e4b92dc404040b01aeacf221347f434f7b67143acd474555eecf";
    "falcosecurity-libs/falcosecurity-plugins-2024-06-05-1-x64-ws.zip" = "3d19595f4ef9de77fef2ec2233000432b7b1e5a0f9353f6c8d99859205e113f8";
    "gnutls/gnutls-3.8.4-2-x64-mingw-dynamic-ws.zip" = "e875c6c34f633c487ce390e25a4d26a3e27d3dca3f9fdfa1d8fd66026d1e257c";
    "krb5/krb5-1.20.1-1-x64-windows-ws.zip" = "a1e5c582afce6e2f72f0f5bd66df2c0f3cc984532a1da5314fc89d7b7f29cdbf";
    "libgcrypt/libgcrypt-1.10.2-2-x64-mingw-dynamic-ws.zip" = "477cfce91d791b34df75a5ad83626f1ac2ee147eff7965e52266a4fc3da0f920";
    "libilbc/libilbc-2.0.2-4-x64-windows-ws.zip" = "4f35a1ffa03c89bf473f38249282a7867b203988d2b6d3d2f0924764619fd5f5";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64ws.zip" = "ee89944a19ab6e1c873bdecb9fc6205d317c41e6da6ec1d30bc892fddfd143da";
    "libpcap/libpcap-1.10.4-1-x64-windows-ws.zip" = "ad18ee1da72ce9df524b8baf9c185f237e534ef8e356c0b3eb3a5d6762004656";
    "libsmi/libsmi-2021-01-15-2-x64-windows-ws.zip" = "ee8e349427d2a4ee9c18fc6b5839bd6df41685ecba03506179c21425e04f3413";
    "libssh/libssh-0.10.6plus-1-x64-mingw-dynamic-ws.zip" = "b4debbc7b5ec34dd998cdc17699526191219e0c593d9797a4bd6147eab020934";
    "lua/lua-5.4.6-unicode-win64-vc14.zip" = "f0c6c7eb28733425b16717beb338d44c041dfbb5c6807e618d96bd754276aaff";
    "lz4/lz4-1.9.4-1-x64-windows-ws.zip" = "179cc6b9a509d7bf07b910389886a00c1cf4738164f32b8e6c245bfb973a4dc7";
    "minizip/minizip-1.3-1-x64-windows-ws.zip" = "eb0bb5fffda5328e192d0d7951ff0254e64dcd736d46909fde7db792c1c53bcc";
    "minizip-ng/minizip-ng-4.0.5-1-x64-windows-ws.zip" = "965c13ec9944ab3515cdfdec36c361f70d76ec773e0897bbe60bdcf1b4eac01b";
    "nghttp2/nghttp2-1.62.1-1-x64-windows-ws.zip" = "381f995791bf48c43a4ab4bdbc68f89d51b8cde8501ded9ce280e3697bb911e5";
    "nghttp3/nghttp3-1.1.0-1-x64-windows-ws.zip" = "e7e181f08ef6e7f592ba0cfef043822c2d516d130c2aad9447a588ade31a258a";
    "opencore-amr/opencore-amr-0.1.6-1-x64-mingw-dynamic-ws.zip" = "013a7b29b62bec123482fed6acd8aed882be3478870c2ec8aec15b7cb81cda02";
    "opus/opus-1.5.1-1-x64-windows-ws.zip" = "30d293b6e4902edae0ca5d747881d9a18f7f03b66a4758bf797f341f89592e6a";
    "sbc/sbc-2.0-1-x64-windows-ws.zip" = "d1a58f977dcffa168b11b280bd10228191582d263b7c901e50cde7c1c43d9c04";
    "snappy/snappy-1.2.1-1-x64-windows-ws.zip" = "e2ffccb26e91881b42d03061dcc728a98af9037705cb4595c8ccbe8d912b5d68";
    "spandsp/spandsp-0.0.6-5-x64-windows-ws.zip" = "cbb18310876ec6f081662253a2d37f5174ac60c58b0b7cd6759852fbcfaa7d7f";
    "speexdsp/speexdsp-1.21.1-1-win64ws.zip" = "d36db62e64ffaee38d9f607bef07d3778d8957ad29757f3eba169eb135f1a4e5";
    "vcpkg-export/vcpkg-export-20240524-1-x64-windows-ws.zip" = "c566f41f20ae87fa4357d204f92cbbe2f236bc1df28c3d106fecfe21a8fbfa11";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zlib-ng/zlib-ng-2.1.5-1-x64-windows-ws.zip" = "a9f90e349d041d464afc1e0926d628ebee02e7093ab9983c5a7808e2b70d7873";
    "zstd/zstd-1.5.6-1-x64-windows-ws.zip" = "f3f59351d273a1c1f2b84b60164556c8d2726155da2148f917d260d9efd16b6e";
}


$Arm64Archives = @{
    "bcg729/bcg729-1.1.1-1-win64armws.zip" = "f4d76b9acf0d0e12e87a020e9805d136a0e8775e061eeec23910a10828153625";
    "brotli/brotli-1.0.9-1-win64armws.zip" = "5ba1b62ebc514d55c3eae85a00ff107e587b6e7cb1275e2d33fcddcd49f8e2af";
    "c-ares/c-ares-1.28.1-1-arm64-windows-ws.zip" = "84954f593d02d1af0ff5c7af1646b0fec5af3260fecda6cda7bbc84f9e343e10";
    "falcosecurity-libs/falcosecurity-libs-0.17.1-2-arm64-ws.zip" = "c9a2e0ae1636b53fd843c87bb136eebe24595d658eb7a82ca9aff2d25b185902";
    "falcosecurity-libs/falcosecurity-plugins-2024-06-05-1-arm64-ws.zip" = "81f7b5a918c3b4cd1c0e08d8e2fadd6859363897d9d6a48f8b408aa67f072b5c";
    "gnutls/gnutls-3.8.4-2-arm64-mingw-dynamic-ws.zip" = "17f28b4a47857db86d9c3f9b7ba12528c8e6368524314fb0fe5ea9303f1a58f9";
    "krb5/krb5-1.20.1-1-arm64-windows-ws.zip" = "6afe3185ea7621224544683a89d7c724d32bef6f1b552738dbc713ceb2151437";
    "libgcrypt/libgcrypt-1.10.2-2-arm64-mingw-dynamic-ws.zip" = "cd42fa2739a204e129d655e1b0dda83ceb27399812b8b2eccddae4a9ecd8d0ce";
    "libilbc/libilbc-2.0.2-4-arm64-windows-ws.zip" = "00a506cc1aac8a2e31856e463a555d899b5a6ccf376485a124104858ccf0be6d";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64armws.zip" = "9996327f301cb4a4de797bc024ad0471acd95c1850a2afc849c57fcc93360610";
    "libpcap/libpcap-1.10.4-1-arm64-windows-ws.zip" = "98dbac265e3617eb0ab1a690902a4989e022d0761098c2753bff4cd0189419b3";
    "libsmi/libsmi-2021-01-15-2-arm64-windows-ws.zip" = "3f5b7507a19436bd6494e2cbc89856a5980950f931f7cf0d637a8e764914d015";
    "libssh/libssh-0.10.6plus-1-arm64-mingw-dynamic-ws.zip" = "2de3a300b0fbb7593c863aa8f302f801a2a1041ced8dfa8d65b7e7b42008c7ef";
    "lua/lua-5.4.6-unicode-arm64-windows-vc14.zip" = "a28c38acde71de5c495420cd8bf480e2e41f1a14bac81503b700fc64a9679b95";
    "lz4/lz4-1.9.4-1-arm64-windows-ws.zip" = "4bb37fb184bcbe350a137df54124faf45fc0871777146b469b7fd08f6dd07337";
    "minizip/minizip-1.3-1-arm64-windows-ws.zip" = "e5b35d064ff10f1ab1ee9193a0965fd1eb3d1e16eab5a905ab3fea9b14fb5afe";
    "minizip-ng/minizip-ng-4.0.5-1-arm64-windows-ws.zip" = "66ccd6ae1f6b0078632f87c9c9cc153ab0015874c8c65d855f8b90beef20cd4e";
    "nghttp2/nghttp2-1.62.1-1-arm64-windows-ws.zip" = "3610c71da9deabf2edab4e09329817911a4e2b493d847035093a7e93d7993c12";
    "nghttp3/nghttp3-1.1.0-1-arm64-windows-ws.zip" = "ae00b65fda2d5e9ffa979be406f127d050a95b0c59654acf7b7411e77b2feb1f";
    "opencore-amr/opencore-amr-0.1.6-1-arm64-mingw-dynamic-ws.zip" = "581ec9e8ee4dde2236b689eec4d39802e2f998baa8d1604a4e91c1da32556b57";
    "opus/opus-1.5.1-1-arm64-windows-ws.zip" = "b50db665b50f12185dacd8efd77cd28eb30e53ac5dcbb09b403e9fb90a9768f4";
    "sbc/sbc-2.0-1-arm64-windows-ws.zip" = "83cfe4a8b6fa5bae253ecacc1c02e6e4c61b4ad9ad0e5e63f0f30422fb6eac96";
    "snappy/snappy-1.2.1-1-arm64-windows-ws.zip" = "71d6987360eb1a10abd0d070768e6b7b250c6ea87feaee044ecbc8864c7e57f4";
    "spandsp/spandsp-0.0.6-5-arm64-windows-ws.zip" = "fdf01e3c33e739ff9399b7d42cd8230c97cb27ce51865a0f06285a8f68206b6c";
    "speexdsp/speexdsp-1.2.1-1-win64armws.zip" = "1759a9193065f27e50dd79dbb1786d24031ac43ccc48c40dca46d8a48552e3bb";
    "vcpkg-export/vcpkg-export-20240524-1-arm64-windows-ws.zip" = "5d1e186b77ec3bc7072253be90b6aa36d7e317bccc382209c1570b60e488000b";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zlib-ng/zlib-ng-2.1.5-1-arm64-windows-ws.zip" = "de3a42d0096a17085b27630402a710b036cc8e3c85029ad37536d929697271e5";
    "zstd/zstd-1.5.6-1-arm64-windows-ws.zip" = "167261f9605a28f8f5a45a2fa400daa5072290a89d5fdc218595da52d57f938b";
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
