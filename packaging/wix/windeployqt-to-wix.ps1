# windeployqt-to-wix
#
# Windeployqt-to-wix - Convert the output of windeployqt to an equivalent set of
# Wix file and component statements.
#
# Copyright 2016 Michael Mann
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

<#
.SYNOPSIS
Creates Wix components required for Qt packaging.

.DESCRIPTION
This script creates an Wix-compatible include file based on the following Qt
versions:

  - 5.3 and later: A list of DLLs and directories based on the output of the
    "windeployqt" utility. Windeployqt lists the DLLs required to run a Qt
    application. (The initial version that shipped with Qt 5.2 is unusable.)

  - 5.2 and earlier: A hard-coded list of Qt DLLs and directories appropriate
    for earlier Qt versions.

  - None: A dummy file.

If building with Qt, QMake must be in your PATH.

.PARAMETER Executable
The path to a Qt application. It will be examined for dependent DLLs.

.PARAMETER FilePath
Output filename.

.INPUTS
-Executable Path to the Qt application.
-FilePath Output Wix include file.

.OUTPUTS
Wix file required to package supporting DLLs.

.EXAMPLE
C:\PS> .\windeployqt-to-wix.ps1 windeployqt.exe ..\..\staging\wireshark.exe qt-dll-manifest.wxs
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [String] $Executable,

    [Parameter(Position=1)]
    [String] $FilePath = "qt-dll-manifest.wxs"
)


try {
    $qtVersion = [version](qmake -query QT_VERSION)
    $wixComponents = "<Wix xmlns=`"http://schemas.microsoft.com/wix/2006/wi`">
<?include InputPaths.wxi ?>
"
    $wixComponents += @("<!-- Qt version " + $qtVersion ; "-->
")

    if ($qtVersion -ge "5.3") {
        # Qt 5.3 or later. Windeployqt is present and works

        $wdqtList = windeployqt `
            --release `
            --no-compiler-runtime `
            --list relative `
            $Executable

        $dllPath = Split-Path -Parent $Executable

        $dllList = "   <Fragment>
     <DirectoryRef Id=`"INSTALLFOLDER`">
"
        $dirList = ""
		$currentDir = ""
		$startDirList = "   <Fragment>
     <DirectoryRef Id=`"INSTALLFOLDER`">
"
		$endDirList = "       </Directory>
     </DirectoryRef>
   </Fragment>
"
		$currentDirList = $startDirList

        $componentGroup = "   <Fragment>
      <ComponentGroup Id=`"CG.QtDependencies`">
"
        foreach ($entry in $wdqtList) {
            $dir = Split-Path -Parent $entry
            if ($dir) {
				if ($dir -ne $currentDir) {
					if ($currentDir -ne "") { # for everything but first directory found
						$currentDirList += $endDirList

						# Previous directory complete, add to list
						$dirList += $currentDirList
					} else {
					}

					$currentDirList = $startDirList + "       <Directory Id=`"dir$dir`" Name=`"$dir`">
"

					$currentDir = $dir
				}


				$wix_name = $entry -replace "[\\|\.]", "_"
                $currentDirList += "           <Component Id=`"cmp$wix_name`" Guid=`"*`">
              <File Id=`"fil$wix_name`" KeyPath=`"yes`" Source=`"`$(var.Staging.Dir)\$entry`" />
           </Component>
"
				$componentGroup += "         <ComponentRef Id=`"cmp$wix_name`" />
"
            } else {

               $dllList += "       <Component Id=`"cmp$entry`" Guid=`"*`">
          <File Id=`"fil$entry`" KeyPath=`"yes`" Source=`"`$(var.Staging.Dir)\$entry`" />
       </Component>
"
			  $componentGroup += "         <ComponentRef Id=`"cmp$entry`" />
"
            }
        }

		#finish up the last directory
		$currentDirList += $endDirList
		$dirList += $currentDirList

		$dllList += "     </DirectoryRef>
   </Fragment>
"
		$componentGroup += "      </ComponentGroup>
   </Fragment>
"

        $wixComponents += $dllList + $dirList + $componentGroup

    } elseif ($qtVersion -ge "5.0") {
        # Qt 5.0 - 5.2. Windeployqt is buggy or not present

        $wixComponents += @"
    <Fragment>
      <DirectoryRef Id=`"INSTALLFOLDER`">
        <Component Id=`"cmpQt5Core_dll`" Guid=`"*`">
          <File Id=`"filQt5Core_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\Qt5Core.dll`" />
        </Component>
        <Component Id=`"cmpQt5Gui_dll`" Guid=`"*`">
          <File Id=`"filQt5Gui_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\Qt5Gui.dll`" />
        </Component>
        <Component Id=`"cmpQt5Widgets_dll`" Guid=`"*`">
          <File Id=`"filQt5Widgets_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\Qt5Widgets.dll`" />
        </Component>
        <Component Id=`"cmpQt5PrintSupport_dll`" Guid=`"*`">
          <File Id=`"filQt5PrintSupport_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\Qt5PrintSupport.dll`" />
        </Component>
        <Component Id=`"cmpQwindows_dll`" Guid=`"*`">
          <File Id=`"filQwindows_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\platforms\qwindows.dll`" />
        </Component>
      </DirectoryRef>
    </Fragment>
    <Fragment>
        <ComponentGroup Id=`"CG.QtDependencies`">
          <ComponentRef Id=`"cmpQt5Core_dll`" />
          <ComponentRef Id=`"cmpQt5Gui_dll`" />
          <ComponentRef Id=`"cmpQt5Widgets_dll`" />
          <ComponentRef Id=`"cmpQt5PrintSupport_dll`" />
          <ComponentRef Id=`"cmpQwindows_dll`" />
        </ComponentGroup>
    </Fragment>
"@

    } else {
        # Assume Qt 4

        $wixComponents += @"
    <Fragment>
      <DirectoryRef Id=`"INSTALLFOLDER`">
        <Component Id=`"cmpQt4Core_dll`" Guid=`"*`">
          <File Id=`"filQt4Core_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\QtCore4.dll`" />
        </Component>
        <Component Id=`"cmpQt4Gui_dll`" Guid=`"*`">
          <File Id=`"filQt4Gui_dll`" KeyPath=`"yes`" Source=`"`$(var.WiresharkQt.Dir)\QtGui4.dll`" />
        </Component>
      </DirectoryRef>
    </Fragment>
    <Fragment>
        <ComponentGroup Id=`"CG.QtDependencies`">
          <ComponentRef Id=`"cmpQt4Core_dll`" />
          <ComponentRef Id=`"cmpQt4Gui_dll`" />
        </ComponentGroup>
    </Fragment>
"@

    }

    $wixComponents += @"
</Wix>
"@

}

catch {

    $wixComponents = "<?xml version=`"1.0`" encoding=`"utf-8`"?>
<Include>
<!--- Qt not configured -->
</Include>
"

}

Set-Content $FilePath @"
<?xml version=`"1.0`" encoding=`"utf-8`"?>
<!--
   Automatically generated by $($MyInvocation.MyCommand.Name)
-->
"@

Add-Content $FilePath $wixComponents