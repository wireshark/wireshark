# SPDX-License-Identifier: GPL-2.0-or-later
#
# Switch the OS appearance to test Wireshark's System/Light/Dark handling.
#
# Usage: set-appearance.ps1 [System|Light|Dark]
# Without an argument the current values are printed.

param(
    [ValidateSet('System', 'Light', 'Dark')]
    [string]$Mode
)

$ErrorActionPreference = "Stop"

$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

if (-not $Mode) {
    $props = Get-ItemProperty -Path $key
    Write-Host "AppsUseLightTheme:   $($props.AppsUseLightTheme)"
    Write-Host "SystemUsesLightTheme: $($props.SystemUsesLightTheme)"
    exit 0
}

switch ($Mode) {
    'Light'  { $value = 1 }
    'Dark'   { $value = 0 }
    # Apps follow the Windows mode.
    'System' { $value = (Get-ItemProperty -Path $key).SystemUsesLightTheme }
}
Set-ItemProperty -Path $key -Name AppsUseLightTheme -Value $value -Type DWord

# Tell running applications about the change.
Add-Type -Namespace Win32 -Name Native -MemberDefinition @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
    string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
$result = [UIntPtr]::Zero
[void][Win32.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero,
    "ImmersiveColorSet", 2, 5000, [ref]$result)
