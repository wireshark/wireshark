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

$Win64CurrentTag = "2018-08-15"
$Win32CurrentTag = "2018-08-15"

# Archive file / SHA256
$Win64Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "c-ares-1.14.0-win64ws.zip" = "91b1e1460bda513375910977a3410afd024575eebc528adecf3abea7814c0ef1";
    "gnutls-3.4.11-1.35-win64ws.zip" = "defc04f430f88e0c1217b98157e38b0e9fc8b4e7ad744c6dd0c24dd17648f9f4";
    "glib2-2.52.2-1.31-win64ws.zip" = "e19a7812db6715c632a5bbf96452ab474a4eaf0c6aaee999323ac7beb7ebe6db";
    "json-glib-1.0.2-4.31-win64ws.zip" = "0b015b4f34384067f4b35cd04cbf745842f9122ae89185e57f8d6223f150bb44";
    "kfw-3-2-2-x64-ws.zip" = "91654ffe0b6d418b369c95bc060414a90f91627e55c19a3e753803c9deb2fe9a";
    "libgcrypt-1.8.3-win64ws.zip" = "53b1c636cb89de308ca4ea01b4990cf1deca7f6c2446189c7ff6e971137ffd76";
    "libsmi-svn-40773-win64ws.zip" = "571fcee71d741bf847c3247d4c2e1c42388ca6a9feebe08fc0d4ce053571d15d";
    "libssh-0.7.3-1-win64ws.zip" = "3a81b9f4a914a46f15243bbb13b6919ef1c20d4bf502c47646caeccff2cbd75c";
    "libxml2-2.9.4-win64ws.zip" = "bb1892f5506f281d8f2b6c8be4fa8e83a9a3fb94c9160466fa59afdc5110d52e";
    "lua-5.2.4_Win64_dllw4_lib.zip" = "cb019c1f771af6c0d6dfb7ddfe162b4984772416349ef1f40871feac6141f805";
    "lz4-1.7.5-win64ws.zip" = "dc946b68238c25cbc216901332d608d7f4b084be2d401210f74ce68b9b93207f";
    "MaxMindDB-1.3.2-win64ws.zip" = "9025c43e9b21ff0bfbaf206b8ed96e2920ef1434107f789e4c7c0c1d8b508952";
    "nghttp2-1.14.0-1-win64ws.zip" = "a4f15854f30b4fbb65cbf150011612e4580683dc9bbb339c632c37e414c938cb";
    "sbc-1.3-1-win64ws.zip" = "08cef6898c421277a6582ef3225d8820f74a037cbd5b6e673a4d8f4593ce80a1";
    "snappy-1.1.3-1-win64ws.zip" = "692a15e70f2cdeca621988a46e936d3651e7feb5176981f2656a5e913c394bcc";
    "spandsp-0.0.6-1-win64ws.zip" = "0e46c61a5a8dca562c36e88a8962a50c1ec1a9fcf89dd05996dac5a79e454527";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "WpdPack_4_1_2.zip" = "ea799cf2f26e4afb1892938070fd2b1ca37ce5cf75fec4349247df12b784edbd";
    "zlib-1.2.11-ws.zip" = "8c963c0594c3c8cea64eb3e32ae9ef9a5af98553e56673bdef0901ff6c692028";
}

$Win32Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win32ws.zip" = "b785ec78dec6bca8252130eb884bfa28c1140001dd7369a535579176de9e4271";
    "c-ares-1.14.0-win32ws.zip" = "7355f3ad6d6ec05541c59e5b398b8dbd9a41bf6776b26d9656d8d54ecd58178e";
    "gnutls-3.4.11-1.36-win32ws.zip" = "10cd21d25b22cfba2566c8d6f5afbbd23d0f8faceb5bc167ccbb8fbb97d6873f";
    "glib2-2.52.2-1.34-win32ws.zip" = "28c426a7b64c1cd5b058c2f25685ddfaebca29083bd8f94fec2a8910ece6faf0";
    "json-glib-1.0.2-4.37-win32ws.zip" = "c5120718ea04c5a966930f6d59a01cb53875a335ef4dad84b8feb411ba0c30f9";
    "kfw-3-2-2-i386-ws-vc6.zip" = "527deb2cf1c3ba0cf743f2b9b8011a22096b54f7ce62fc7ba31b520bbac0e802";
    "libgcrypt-1.8.3-win32ws.zip" = "409b72f2809019050cca91b9e670047c50a0752ff52999089178da54ef926393";
    "libsmi-svn-40773-win32ws.zip" = "44bc81edfeb8948322ca365fc632e419383907c305cc922e6b74fdbb13827958";
    "libssh-0.7.3-1-win32ws.zip" = "b02f0d318175194ac538a24c9c9fc280a0ecad69fb3afd4945c106b4b7c4fa6f";
    "libxml2-2.9.4-win32ws.zip" = "147e521abacdd96913f7f94d1da44d59ee138e510922f3c1e03e485c8c9d8d1c";
    "lua-5.2.4_Win32_dllw4_lib.zip" = "a4e93f923b23cfe2ec2f2150a09639cd6dd822e64dd50f1db253affa1afd360b";
    "lz4-1.7.5-win32ws.zip" = "1b2e4b509163bc5039c0694369b9e40ba27cdbf4c4c88fcd454ba6a34c79b41b";
    "MaxMindDB-1.3.2-win32ws.zip" = "5c8b4bf3092da8fad6edb005a5283c6a74b7e115a50da010953eed77d33c11b7";
    "nghttp2-1.14.0-1-win32ws.zip" = "939ec18c81fed2e44270dc924fad8beffe90a74300cc98360442300fb0a5c292";
    "sbc-1.3-1-win32ws.zip" = "ad37825e9ace4b849a5442c08f1ed7e30634e6b774bba4307fb86f35f82e71ba";
    "snappy-1.1.3-1-win32ws.zip" = "2508ef7c5d27655c356d7b86a00ac887fc178eab5df63595b8793953dae5c379";
    "spandsp-0.0.6-1-win32ws.zip" = "3c25f2f4d641d4257ec9922f6db77346a8eed2e360e7d0e27b828ade19c4705b";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "WpdPack_4_1_2.zip" = "ea799cf2f26e4afb1892938070fd2b1ca37ce5cf75fec4349247df12b784edbd";
    "zlib-1.2.11-ws.zip" = "8c963c0594c3c8cea64eb3e32ae9ef9a5af98553e56673bdef0901ff6c692028";
}

# Subdirectory to extract an archive to
$ArchivesSubDirectory = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
    "lua-5.2.4_Win64_dllw4_lib.zip" = "lua5.2.4";
    "lua-5.2.4_Win32_dllw4_lib.zip" = "lua5.2.4";
}

# Plain file downloads

$Win32Files = @{
    "WinPcap_4_1_3.exe" = "fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de";
    "USBPcapSetup-1.2.0.4.exe" = "0a5ac30b0264e058f262e9c28e5865af7b836620ca5d68bb4bb42c9a808f7a43";
}

$Win64Files = @{
    "WinPcap_4_1_3.exe" = "fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de";
    "USBPcapSetup-1.2.0.4.exe" = "0a5ac30b0264e058f262e9c28e5865af7b836620ca5d68bb4bb42c9a808f7a43";
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
    "c-ares-1.9.1-1-win??ws"
    "c-ares-1.1*-win??ws"
    "gnutls-3.1.22-*-win??ws"
    "gnutls-3.2.15-*-win??ws"
    "gnutls-3.4.11-*-win??ws"
    "glib2-2.*-win??ws"
    "gtk2"
    "gtk3"
    "json-glib-1.0.2-*-win??ws"
    "kfw-3-2-2-final"
    "kfw-3-2-2-i386-ws-vc6"
    "kfw-3-2-2-x64-ws"
    "libgcrypt-*-win??ws"
    "libsmi-0.4.8"
    "libsmi-svn-40773-win??ws"
    "libssh-0.7.?-win??ws"
    "libxml2-*-win??ws"
    "lua5.1.4"
    "lua5.2.?"
    "lz4-*-win??ws"
    "MaxMindDB-1.3.2-win??ws"
    "nghttp2-*-win??ws"
    "portaudio_v19"
    "portaudio_v19_2"
    "sbc-1.3-win??ws"
    "snappy-1.1.3-win??ws"
    "spandsp-0.0.6-win??ws"
    "upx301w"
    "upx303w"
    "user-guide"
    "zlib-1.2.5"
    "zlib-1.2.8"
    "zlib-1.2.*-ws"
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
