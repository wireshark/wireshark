-- init.lua
--
-- initialize wireshark's lua
--
--  This file is going to be executed before any other lua script.
--  It can be used to load libraries, disable functions and more.
--
-- $Id$
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

-- Set disable_lua to true to disable Lua support.
disable_lua = false

if disable_lua then
    return
end

-- If set and we are running with special privileges this setting
-- tells whether scripts other than this one are to be run.
run_user_scripts_when_superuser = false


-- disable potentialy harmful lua functions when running superuser
if running_superuser then
    local hint = "has been disabled due to running Wireshark as superuser. See http://wiki.wireshark.org/CaptureSetup/CapturePrivileges for help in running Wireshark as an unprivileged user."
    local disabled_lib = {}
    setmetatable(disabled_lib,{ __index = function() error("this package ".. hint) end } );

    dofile = function() error("dofile " .. hint) end
    loadfile = function() error("loadfile " .. hint) end
    loadlib = function() error("loadlib " .. hint) end
    require = function() error("require " .. hint) end
    os = disabled_lib
    io = disabled_lib
    file = disabled_lib
end

-- to avoid output to stdout which can cause problems lua's print ()
-- has been suppresed so that it yields an error.
-- have print() call info() instead.
if gui_enabled() then
    print = info
end

-- %WTAP_ENCAPS%

-- %FT_TYPES%

-- %BASES%

-- %ENCODINGS%

-- %EXPERT%

-- %MENU_GROUPS%

-- other useful constants
GUI_ENABLED = gui_enabled()
DATA_DIR = datafile_path()
USER_DIR = persconffile_path()

dofile(DATA_DIR.."console.lua")
--dofile(DATA_DIR.."dtd_gen.lua")
