# windeployqt-to-nsh
#
# Convert the output of windeployqt to an equivalent set of NSIS "File"
# function calls.

Param(
    [string[]] $Windeployqt,
    [string[]] $Executable
)

$wdqtList = & $Windeployqt `
    --release `
    --no-compiler-runtime `
    --list relative `
    $Executable

$dllPath = Split-Path -Parent $Executable

$dllList = @()
$dirList = @()

foreach ($entry in $wdqtList) {
    $dir = Split-Path -Parent $entry
    if ($dir) {
        $dirList += $dir
    } else {
        $dllList += $entry
    }
}

$dirList = $dirList | Sort-Object | Get-Unique

foreach ($entry in $dllList) {
    write-output "File `"$dllPath\$entry`""
}

foreach ($entry in $dirList) {
    write-output "File /r `"$dllPath\$entry`""
}

