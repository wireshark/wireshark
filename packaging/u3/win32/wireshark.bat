:: wireshark.bat
:: A batch script to run wireshark from the files that
:: constitute the U3 package.
:: Also used to test the U3 package build.
::
:: $Id$ 
::
:: Wireshark - Network traffic analyzer
:: By Gerald Combs <gerald@wireshark.org>
:: Copyright 1998 Gerald Combs
:: This program is free software; you can redistribute it and/or
:: modify it under the terms of the GNU General Public License
:: as published by the Free Software Foundation; either version 2
:: of the License, or (at your option) any later version.
::
:: This program is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
:: GNU General Public License for more details.
::
:: You should have received a copy of the GNU General Public License
:: along with this program; if not, write to the Free Software
:: Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
::

@echo off
SETLOCAL

SET U3_DEVICE_SERIAL=0000060414068917
SET U3_DEVICE_PATH=%~d0
SET U3_DEVICE_DOCUMENT_PATH=%CD%\data

SET U3_DEVICE_VENDOR="Wireshark Developers"
SET U3_DEVICE_PRODUCT="Non-U3 Drive"
SET U3_DEVICE_VENDOR_ID=0000

SET U3_APP_DATA_PATH=%CD%\data
SET U3_HOST_EXEC_PATH=%CD%\host
SET U3_DEVICE_EXEC_PATH=%CD%\device

SET U3_ENV_VERSION=1.0
SET U3_ENV_LANGUAGE=1033

"%U3_HOST_EXEC_PATH%\wireshark.exe" %*
