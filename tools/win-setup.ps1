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
    "bcg729/bcg729-1.0.4-win64ws.zip" = "9a095fda4c39860d96f0c568830faa6651cd17635f68e27aa6de46c689aa0ee2";
    "brotli/brotli-1.0.9-1-win64ws.zip" = "3f8d24aec8668201994327ff8d8542fe507d1d468a500a1aec50d0415f695aab";
    "c-ares/c-ares-1.28.1-1-x64-windows-ws.zip" = "6509df8e15ed67e87fac84a3b0acaa7b804b59f272fdf9decfb6157d241e73da";
    "falcosecurity-libs/falcosecurity-libs-0.18.1-1-x64-ws.zip" = "2b7751f179460f84d41fdc20dc0f67c740f0213b57f9b28075a5903c6e850e5a";
    "falcosecurity-libs/falcosecurity-plugins-2024-07-30-2-x64-ws.zip" = "964e9df1af2a115238c2370a5d2ba00c39f080a9701cf375ea829fdc2b63214a";
    "gnutls/gnutls-3.8.4-2-x64-mingw-dynamic-ws.zip" = "e875c6c34f633c487ce390e25a4d26a3e27d3dca3f9fdfa1d8fd66026d1e257c";
    "krb5/krb5-1.21.3-1-x64-windows-ws.zip" = "49b83da4baa476c4c31ed3ee463f962114a469b8c3d601db68bdb6bc03a88e42";
    "libgcrypt/libgcrypt-1.10.2-2-x64-mingw-dynamic-ws.zip" = "477cfce91d791b34df75a5ad83626f1ac2ee147eff7965e52266a4fc3da0f920";
    "libilbc/libilbc-2.0.2-4-x64-windows-ws.zip" = "4f35a1ffa03c89bf473f38249282a7867b203988d2b6d3d2f0924764619fd5f5";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64ws.zip" = "ee89944a19ab6e1c873bdecb9fc6205d317c41e6da6ec1d30bc892fddfd143da";
    "libsmi/libsmi-2021-01-15-2-x64-windows-ws.zip" = "ee8e349427d2a4ee9c18fc6b5839bd6df41685ecba03506179c21425e04f3413";
    "libssh/libssh-0.11.1-1-x64-mingw-dynamic-ws.zip" = "bce4f23eac58c96bd772844983ae5ce786b9f894be4a50c71135514a30c46ed4";
    "lua/lua-5.4.6-unicode-win64-vc14.zip" = "f0c6c7eb28733425b16717beb338d44c041dfbb5c6807e618d96bd754276aaff";
    "lz4/lz4-1.10.0-1-x64-windows-ws.zip" = "8b838f68cc90efa2d7c37f2bc651d153487bc336525d67f9c224a3e4bccf3583";
    "minizip/minizip-1.3-1-x64-windows-ws.zip" = "eb0bb5fffda5328e192d0d7951ff0254e64dcd736d46909fde7db792c1c53bcc";
    "minizip-ng/minizip-ng-4.0.7-1-x64-windows-ws.zip" = "aa47457f9e4eb693a981fab9ad1ad46504607e30c955c5e1118c6437b421b164";
    "nghttp2/nghttp2-1.62.1-1-x64-windows-ws.zip" = "381f995791bf48c43a4ab4bdbc68f89d51b8cde8501ded9ce280e3697bb911e5";
    "nghttp3/nghttp3-1.1.0-1-x64-windows-ws.zip" = "e7e181f08ef6e7f592ba0cfef043822c2d516d130c2aad9447a588ade31a258a";
    "opencore-amr/opencore-amr-0.1.6-1-x64-mingw-dynamic-ws.zip" = "013a7b29b62bec123482fed6acd8aed882be3478870c2ec8aec15b7cb81cda02";
    "opus/opus-1.5.1-1-x64-windows-ws.zip" = "30d293b6e4902edae0ca5d747881d9a18f7f03b66a4758bf797f341f89592e6a";
    "sbc/sbc-2.0-1-x64-windows-ws.zip" = "d1a58f977dcffa168b11b280bd10228191582d263b7c901e50cde7c1c43d9c04";
    "snappy/snappy-1.2.1-1-x64-windows-ws.zip" = "e2ffccb26e91881b42d03061dcc728a98af9037705cb4595c8ccbe8d912b5d68";
    "spandsp/spandsp-0.0.6-5-x64-windows-ws.zip" = "cbb18310876ec6f081662253a2d37f5174ac60c58b0b7cd6759852fbcfaa7d7f";
    "speexdsp/speexdsp-1.21.1-1-win64ws.zip" = "d36db62e64ffaee38d9f607bef07d3778d8957ad29757f3eba169eb135f1a4e5";
    "vcpkg-export/vcpkg-export-20250124-1-x64-windows-ws.zip" = "8587711d1b95fe3708355b71139a28036e0c17f60840a8805f014b70c036d460";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zlib-ng/zlib-ng-2.2.3-1-x64-windows-ws.zip" = "8b4e5ba1b61688eccb7e315c2f4ce1ef0c4301172f265bd41455e1df6a5a9522";
    "zstd/zstd-1.5.6-1-x64-windows-ws.zip" = "f3f59351d273a1c1f2b84b60164556c8d2726155da2148f917d260d9efd16b6e";
}


$Arm64Archives = @{
    "bcg729/bcg729-1.1.1-1-win64armws.zip" = "f4d76b9acf0d0e12e87a020e9805d136a0e8775e061eeec23910a10828153625";
    "brotli/brotli-1.0.9-1-win64armws.zip" = "5ba1b62ebc514d55c3eae85a00ff107e587b6e7cb1275e2d33fcddcd49f8e2af";
    "c-ares/c-ares-1.28.1-1-arm64-windows-ws.zip" = "84954f593d02d1af0ff5c7af1646b0fec5af3260fecda6cda7bbc84f9e343e10";
    "falcosecurity-libs/falcosecurity-libs-0.18.1-1-arm64-ws.zip" = "da0f3631beaf10f499819c018cb400686195a615bf39b1904ed43a008d18672b";
    "falcosecurity-libs/falcosecurity-plugins-2024-07-30-2-arm64-ws.zip" = "1d4b7cd664987f6efc3a2c5beb770119bafe8ba6ad8ad37cb7ed4fd07a2cf649";
    "gnutls/gnutls-3.8.4-2-arm64-mingw-dynamic-ws.zip" = "17f28b4a47857db86d9c3f9b7ba12528c8e6368524314fb0fe5ea9303f1a58f9";
    "krb5/krb5-1.21.3-1-arm64-windows-ws.zip" = "26166173cb653fdf2153c311a9f611a76575359393222cebd5228842632a0ccb";
    "libgcrypt/libgcrypt-1.10.2-2-arm64-mingw-dynamic-ws.zip" = "cd42fa2739a204e129d655e1b0dda83ceb27399812b8b2eccddae4a9ecd8d0ce";
    "libilbc/libilbc-2.0.2-4-arm64-windows-ws.zip" = "00a506cc1aac8a2e31856e463a555d899b5a6ccf376485a124104858ccf0be6d";
    "libmaxminddb/libmaxminddb-1.4.3-1-win64armws.zip" = "9996327f301cb4a4de797bc024ad0471acd95c1850a2afc849c57fcc93360610";
    "libsmi/libsmi-2021-01-15-2-arm64-windows-ws.zip" = "3f5b7507a19436bd6494e2cbc89856a5980950f931f7cf0d637a8e764914d015";
    "libssh/libssh-0.11.1-1-arm64-mingw-dynamic-ws.zip" = "aca24901203612f3feef0d7a8954afd81379a9a35486565a13147bf10d5f0f1b";
    "lua/lua-5.4.6-unicode-arm64-windows-vc14.zip" = "a28c38acde71de5c495420cd8bf480e2e41f1a14bac81503b700fc64a9679b95";
    "lz4/lz4-1.10.0-1-arm64-windows-ws.zip" = "ee51fbf87bf359fa7835be89797c3488daf502e36e26337b0e649030aab7a09b";
    "minizip/minizip-1.3-1-arm64-windows-ws.zip" = "e5b35d064ff10f1ab1ee9193a0965fd1eb3d1e16eab5a905ab3fea9b14fb5afe";
    "minizip-ng/minizip-ng-4.0.7-1-arm64-windows-ws.zip" = "f0068dff1952b66f1bd8611461325589dc09ae8d04493fd7825f94d58960e34a";
    "nghttp2/nghttp2-1.62.1-1-arm64-windows-ws.zip" = "3610c71da9deabf2edab4e09329817911a4e2b493d847035093a7e93d7993c12";
    "nghttp3/nghttp3-1.1.0-1-arm64-windows-ws.zip" = "ae00b65fda2d5e9ffa979be406f127d050a95b0c59654acf7b7411e77b2feb1f";
    "opencore-amr/opencore-amr-0.1.6-1-arm64-mingw-dynamic-ws.zip" = "581ec9e8ee4dde2236b689eec4d39802e2f998baa8d1604a4e91c1da32556b57";
    "opus/opus-1.5.1-1-arm64-windows-ws.zip" = "b50db665b50f12185dacd8efd77cd28eb30e53ac5dcbb09b403e9fb90a9768f4";
    "sbc/sbc-2.0-1-arm64-windows-ws.zip" = "83cfe4a8b6fa5bae253ecacc1c02e6e4c61b4ad9ad0e5e63f0f30422fb6eac96";
    "snappy/snappy-1.2.1-1-arm64-windows-ws.zip" = "71d6987360eb1a10abd0d070768e6b7b250c6ea87feaee044ecbc8864c7e57f4";
    "spandsp/spandsp-0.0.6-5-arm64-windows-ws.zip" = "fdf01e3c33e739ff9399b7d42cd8230c97cb27ce51865a0f06285a8f68206b6c";
    "speexdsp/speexdsp-1.2.1-1-win64armws.zip" = "1759a9193065f27e50dd79dbb1786d24031ac43ccc48c40dca46d8a48552e3bb";
    "vcpkg-export/vcpkg-export-20250124-1-arm64-windows-ws.zip" = "29f234a5dc64c43e1b3aca8c47561ea877cdfc21abfeafc97174770023a097dc";
    "WinSparkle/WinSparkle-0.8.0-4-gb320893.zip" = "3ae42326bcd34594bc21b1e7948863a839ee76e87d9f4cf6b59b9d9f9a083881";
    "zlib-ng/zlib-ng-2.2.3-1-arm64-windows-ws.zip" = "bea4250059565c3cc49a382d8ec3f82b70c51c3ccca41c5d3daec6862d22d8f8";
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
