echo off
rem cleanbld.bat
rem Script to clean up from a build on another platform
rem
rem $Id: cleanbld.bat,v 1.1 2001/07/13 08:14:03 guy Exp $
rem
rem Ethereal - Network traffic analyzer
rem By Gerald Combs <gerald@ethereal.com>
rem Copyright 1998 Gerald Combs
rem 
rem This program is free software; you can redistribute it and/or
rem modify it under the terms of the GNU General Public License
rem as published by the Free Software Foundation; either version 2
rem of the License, or (at your option) any later version.
rem 
rem This program is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTY; without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
rem GNU General Public License for more details.
rem 
rem You should have received a copy of the GNU General Public License
rem along with this program; if not, write to the Free Software
rem Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
rem
rem Remove the config.h files that are built from config.h.win32 files,
rem so that a build will reconstruct them; this should be run the first
rem time you do a Microsoft Visual C++ build, so that, for example, if
rem you've done a UNIX build, the build doesn't use the config.h files
rem from that build (using those config.h files will cause the build
rem to fail).
rem
del/f config.h
del/f epan\config.h
del/f wiretap\config.h
