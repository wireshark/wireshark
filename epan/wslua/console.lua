-- console
-- A console and a window to execute commands in lua
--
-- (c) 2006 Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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


if (gui_enabled()) then 
	local function evaluate_lua()
		local w = TextWindow.new("Evaluate Lua")
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

	local console_open = false

	local function run_console()
		if console_open then return end
		console_open = true

		local w = TextWindow.new("Console")

		local orig = {
			critical = critical,
			warn = warn,
			message = message,
			info = info,
			debug = debug
		}

		function critical(txt)  w:append( "CRITICAL: " .. txt .. "\n") end
		function warn(txt)  w:append( "WARN: " .. txt .. "\n") end
		function message(txt)  w:append( "MESSAGE: " .. txt .. "\n") end
		function info(txt)  w:append( "INFO: " .. txt .. "\n") end
		function debug(txt)  w:append( "DEBUG: " .. txt .. "\n") end

		function at_close()
			critical = orig.critical
			warn = orig.warn
			message = orig.message
			info = orig.info
			debug = orig.debug

			console_open = false
		end

		w:set_atclose(at_close)
	end

	register_menu("Evaluate Lua",evaluate_lua,MENU_TOOLS)
	register_menu("Lua Console",run_console,MENU_TOOLS)
end