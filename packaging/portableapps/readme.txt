Portable Wireshark
==================

This directory contains experimental packaging for running Wireshark under the Portable Apps 
(http://www.portableapps.com/). 

Currently only an additional menu item for Wireshark is added - the other tools could be added to Portable Apps menu if required.

WinPcap
=======

If you want to capture packets, then WinPcap needs to be installed. Wireshark Portable will try and install WinPcap if it doesn't find it installed on the local machine. If it does install it, it will uninstall it when Wireshark Portable quits.
A quieter install/de-install for WinPcap would help matters - but ultimately a minimal installation mechanism needs to be identified for WinPcap. But that is not for the Wireshark forum.

NSIS
====

The Portable Apps packaging uses the NullSoft Scriptable Installer System (NSIS) to create a installation package to install onto the USB drive, and a launcher to launch Wireshark from the USB drive.

NSIS is used by the standard Win32 installation mechansim (packaging/nsis) but an additional plug-in is required for the Wireshark Portable launcher. This is now automatically downloaded and installed from the wireshark-win32-libs repository.

INI Settings
============
The Wireshark Portable Launcher will look for an ini file called WiresharkPortable.ini within its directory.  It is only necessary to have a ini file if you wish to change the default configuration. 
There is an example INI included with this package to get you started.  The INI file is formatted as follows:

[WiresharkPortable]
WiresharkDirectory
WiresharkExecutable
AdditionalParameters
DisableWinPcapInstall
WinPcapInstaller
MSVCRedist

The WiresharkDirectory entry should be set to the *relative* path to the directory containing the Wireshark Portable Launcher (WiresharkPortable.exe). This entry must be present. 

The WiresharkExecutable entry allows you to set the Wireshark Portable Launcher to use an alternate EXE call to launch Wireshark. 

The AdditionalParameters entry allows you to pass additional commandline parameter entries to wireshark.exe. 

The DisableWinPcapInstall allows you to disable the installation of WinPcap, even if it it not present on the host system.

The WinPcapInstaller allows you to specify a different WinPcap installer than the default one included in the distribution. For example, if you download a later version.

The MSVCRedist allows you to specify a different redistributable package to be used than the default one included in the distribution.
