# MakeUninstall.ps1
#
# Runs the uninstall_installer to create the uninstall.exe that can be signed
# Uses set __COMPAT_LAYER=RunAsInvoker to not request elevation
#
# Copyright 2020 Graham Bloice <graham.bloice@trihedral.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

#requires -version 2

<#
.SYNOPSIS
Runs the uninstall_<application>_installer without invoking UAC.

.DESCRIPTION
This script runs the uninstall_<application>_installer that creates an
uninstall exe but without invoking a UAC elevation prompt that is required
by the uninstaller

.PARAMETER Executable
The path to the uninstall_<application>_installer.exe

.INPUTS
-Executable Path to the uninstaller installer.

.OUTPUTS
An unsigned uninstall-<application>.exe for signing

.EXAMPLE
C:\PS> .\makeUninstall.ps1 run\RelWithDebInfo\uninstall_wireshark_installer.exe
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [String] $Executable
)

# Stop the process requesting elevation, runs as the user
$env:__COMPAT_LAYER = "RunAsInvoker"

# And run the process
Start-Process $Executable -Wait -NoNewWindow
