-- init.lua
--
-- initilaize ethereal's lua
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


-- If lua is to be disabled even if it was installed uncomment the following
-- line.
-- disable_lua = true; do return end;


-- If set and we are running with special privileges this setting
-- tells whether scripts other than this one are to be run.
run_user_scripts_when_superuser = false

-- disable potentialy harmful lua functions when running superuser
if running_superuser then
    dofile = function() error("dofile has been disabled") end
    loadfile = function() error("loadfile has been disabled") end
    loadlib = function() error("loadlib has been disabled") end
    require = function() error("require has been disabled") end
    os = {}
    io = {}
    file = {}
end

-- to avoid output to stdout which can caause problems lua's print ()
-- has been suppresed so that it yields an error.
-- have print() call info() instead.
print = info

-- %WTAP_ENCAPS%

-- %FT_TYPES%

-- %BASES%

-- %EXPERT%

-- %MENU_GROUPS%

-- Console to execute commands in lua
function wslua_console()
	local w = TextWindow.new("Lua Console")
	w:set_editable(TRUE)

	function eval()
		local text = string.gsub(w:get_text(),"%c*--%[%[.*--%]%]$","")
		text = string.gsub(text,"^=","return ")

		local result = assert(loadstring(text))()

		if (result ~= nil) then
			w:set(text .. '\n\n--[[ Result:\n' .. result .. '\n--]]')
		else
			w:set(text .. '\n\n--[[  Evaluated --]]')
		end
	end

   w:add_button("Evaluate",eval)
end

register_menu("Lua Console",wslua_console,MENU_TOOLS)

