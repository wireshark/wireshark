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
    [ValidateScript({$_ -like "*[/\]wireshark-*-libs"})]
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

$Win64CurrentTag = "2021-12-09"
$Win32CurrentTag = "2021-12-09"

# Archive file / SHA256
$Win64Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "brotli-1.0.9-1-win64ws.zip" = "3f8d24aec8668201994327ff8d8542fe507d1d468a500a1aec50d0415f695aab";
    "c-ares-1.17.2-1-win64ws.zip" = "6572a9dac4317b7a84544f3f85b1028a715c73e4f063c0e1f36ca59168d04070";
    "gnutls-3.6.3-1-win64ws.zip" = "994ac2578e7b4ca01e589ab2598927d53f7370bc3ff679f3006b0e6bb7a06df4";
    "krb5-1.17-1-win64ws.zip" = "1f4a7ab86ae331ea9e58c9776a60def81ae9fe622882b2e8da2ad6ce6f6fb1d8";
    "libgcrypt-1.8.3-win64ws.zip" = "53b1c636cb89de308ca4ea01b4990cf1deca7f6c2446189c7ff6e971137ffd76";
    "libilbc-2.0.2-3-win64ws.zip" = "d7baeb98627c405bd7c3e41d6b07c4ea4f0f5db88436e566148320afd10cbb66";
    "libmaxminddb-1.4.3-1-win64ws.zip" = "ee89944a19ab6e1c873bdecb9fc6205d317c41e6da6ec1d30bc892fddfd143da";
    "libpcap-1.10.1-1-win64ws.zip" = "59f8e0e90a3ab5671df561266ed2b02870a6f8f3a895b80c9db19fea9a12ffb2";
    "libsmi-svn-40773-win64ws.zip" = "571fcee71d741bf847c3247d4c2e1c42388ca6a9feebe08fc0d4ce053571d15d";
    "libssh-0.9.5-win64ws.zip" = "3226fcb89969a77643bd2bca7a1ff6b5a79261b680a09a6bfedb3d40f7a187e3";
    "lua-5.2.4-unicode-win64-vc14.zip" = "e8968d2c7871ce1ea82cbd29ac1b3a2c59d3dec25e483c5e12de85df66f5d928";
    "lz4-1.9.3-1-win64ws.zip" = "7129515893ffdc439f4ffe9673c4bc43f9042e910bb2607e68dde6b99a1ab058";
    "minizip-1.2.11-4-win64ws.zip" = "dd6bf24e2d946465ad19aa4f8c38e0db91da6585887935de68011982cd6fb2cb";
    "nghttp2-1.44.0-1-win64ws.zip" = "30e4925d48bbd401b03ce6502e8df01f81f114366f28682206e08423486cf161";
    "opus-1.3.1-3-win64ws.zip" = "1f7a55a6d2d7215dffa4a43bca8ca05024bd4ba1ac3d0d0c405fd38b09cc2205";
    "pcre2-10.39-1-win64ws.zip" = "d8b381515c4bae97a28a6b0a3faf66a4f890e85ef75f8ef9501ffa091db6ff8a";
    "sbc-1.3-1-win64ws.zip" = "08cef6898c421277a6582ef3225d8820f74a037cbd5b6e673a4d8f4593ce80a1";
    "snappy-1.1.9-1-win64ws.zip" = "fa907724be019bcc55d27ebe88257ba8898b5c38b719099b8164ac78600d81cc";
    "spandsp-0.0.6-2-win64ws.zip" = "2eb8278633037f60f44815ea1606486ab5dcdf3bddc500b20c9fe356856236b2";
    "vcpkg-export-20210609-1-win64ws.zip" = "2207112ecae2d93e64405cb33e625d37c85f9b9db90b440a4d0f0362346564e4";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "zstd-1.4.0-win64ws.zip" = "154199227bdfdfa608972bcdcea38e20768937085e5a59a8fa06c72d07b00d6b";
}

$Win32Archives = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "09d637f28a79b1d2ecb09f35436271a90c0f69bd0a1ee82b803abaaf63c18a69";
    "bcg729-1.0.4-win32ws.zip" = "b785ec78dec6bca8252130eb884bfa28c1140001dd7369a535579176de9e4271";
    "brotli-1.0.9-1-win32ws.zip" = "37ce13b3d41f025b8f6ca962e7fbacca6421d9b3b58f2ebaa81b1262d0a972ba";
    "c-ares-1.17.2-1-win32ws.zip" = "ce901f69b46697a52bf239a5a77d6d389c06d637ad2d1bebfaf1333fc4f89e46";
    "gnutls-3.6.3-1-win32ws.zip" = "42d8313ffb888f525d6c39330c39bcc2182e68ee8433a09dd85e1f1e1474f592";
    "krb5-1.17-1-win32ws.zip" = "f90cac08355ccfe624652d3e05f8e2e077b8830382315d4ea0a6fa52af08260b";
    "libgcrypt-1.8.3-win32ws.zip" = "409b72f2809019050cca91b9e670047c50a0752ff52999089178da54ef926393";
    "libilbc-2.0.2-3-win32ws.zip" = "b87967b5e46cd96d178bc3b3dbba5a75c069ef28ab8a86838c9d004690703997";
    "libmaxminddb-1.4.3-1-win32ws.zip" = "956f33daa63ce671df4c3e9210308f105e193e7a62c2d947f786d441758ed5e4";
    "libpcap-1.10.1-1-win32ws.zip" = "145060e567d19b599e2e91e6c3e8023c3d2219acde4bf8bd45ec12e951d57909";
    "libsmi-svn-40773-win32ws.zip" = "44bc81edfeb8948322ca365fc632e419383907c305cc922e6b74fdbb13827958";
    "libssh-0.9.5-win32ws.zip" = "0cbdc1b9a65c38e601fda6df3fcdd76f8a0b83e98fa5c836764e1592d8a79194";
    "lua-5.2.4-unicode-win32-vc14.zip" = "ca2368a83f623674178e9441f71fb791e3c0b46f208e3dac28c6ac735f034bff";
    "lz4-1.9.3-1-win32ws.zip" = "4b74f9f41a1d364909d9815500dcd10931aa4fbed7fcc39503dfa84c9fcd58d3";
    "minizip-1.2.11-4-win32ws.zip" = "41e113930902c2519c4644e8307a0cc51c5855e001e1e69768c48deb376142d0";
    "nghttp2-1.44.0-1-win32ws.zip" = "3a19e076523ef263f6900749f345725b4e8bf2c4027e0f349404ad81c4613bde";
    "opus-1.3.1-3-win32ws.zip" = "9700b14c8945fcfed2188b806a2ee7e8628922c22569a4c5183075f3dc133177";
    "pcre2-10.39-1-win32ws.zip" = "6ad963036bd913fba680e867bbcf8bf9c2995c80dd0401bfa6bb35328c640c70";
    "sbc-1.3-1-win32ws.zip" = "ad37825e9ace4b849a5442c08f1ed7e30634e6b774bba4307fb86f35f82e71ba";
    "snappy-1.1.9-1-win32ws.zip" = "28bae646f1dff80ceb1b1756b1fdec0ebc47580a412a8a4980f3d61c63cb0858";
    "spandsp-0.0.6-2-win32ws.zip" = "31a4b5ca228c719ab4190e1b46801f1483efb8756f1e33d10ecc915244612fca";
    "vcpkg-export-20210609-1-win32ws.zip" = "da544758352e31aed6cf9e62a6670df218b3d369cd113a462e94010b0ef8e472";
    "WinSparkle-0.5.7.zip" = "56d396ef0c4e8b0589ea74134e484376ca6459d972cd1ab1da6b9624d82e6d04";
    "zstd-1.4.0-win32ws.zip" = "9141716d4d749e67dad40d4aab6bbb3206085bf68e5acb03baf1e5667aa0b6f5";
}

# Subdirectory to extract an archive to
$ArchivesSubDirectory = @{
    "AirPcap_Devpack_4_1_0_1622.zip" = "AirPcap_Devpack_4_1_0_1622";
}

# Plain file downloads

$Win32Files = @{
    "npcap-1.60.exe" = "87d3624772b8272767a3a4ffcceecc3052489cd09e494a6c352dce5e5efa4070";
    "USBPcapSetup-1.5.4.0.exe" = "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622";
}

$Win64Files = @{
    "npcap-1.60.exe" = "87d3624772b8272767a3a4ffcceecc3052489cd09e494a6c352dce5e5efa4070";
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
    "brotli-1.0.*-win??ws"
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
    "portaudio_v19"
    "portaudio_v19_2"
    "sbc-1.3-win??ws"
    "snappy-1.1.*-win??ws"
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

function DownloadArchive($fileName, $checksum, $subDir) {
    DownloadFile $fileName $checksum
    $archiveFile = "$Destination\$fileName"
    $archiveDir = "$Destination\$subDir"
    if ($subDir -and -not (Test-Path $archiveDir -PathType 'Container')) {
        New-Item -ItemType Directory -Path $archiveDir > $null
    }

    $activity = "Extracting into $($archiveDir)"
    Write-Progress -Activity "$activity" -Status "Extracting $archiveFile using CMake ..."
    Push-Location "$archiveDir"
    & cmake -E tar xf "$archiveFile" 2>&1 | Set-Variable -Name CMakeOut
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
$destinationTag = "INVALID"
$tagFile = "current_tag.txt"
if ((Test-Path $tagFile -PathType 'Leaf') -and -not ($Force)) {
    $destinationTag = Get-Content $tagFile
}

if ($destinationTag -ne $CurrentTag) {
    Write-Output "Tag $CurrentTag not found. Refreshing."
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
