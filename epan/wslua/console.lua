-- console
-- A console and a window to execute commands in lua
--
-- (c) 2006 Luis E. Garcia Ontanon <luis@ontanon.org>
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- SPDX-License-Identifier: GPL-2.0-or-later


if (gui_enabled()) then 
	-- Note that everything is "local" to this "if then" 
	-- this way we don't add globals

	-- Evaluate Window
	local function evaluate_lua()
		local w = TextWindow.new("Evaluate Lua")
		w:set_editable()

		-- button callback
		local function eval()
			-- get the window's text and remove the result 
			local text = string.gsub(w:get_text(),"%c*--%[%[.*--%]%]$","")

			-- if the text begins with '=' then convert = into return
			text = string.gsub(text,"^=","return ")

			-- evaluate text
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

	local date = rawget(os,"date") -- use rawget to avoid disabled's os.__index

	if type(date) ~= "function" then
		-- 'os' has been disabled, use a dummy function for date
		date = function() return "" end
	end

	-- Console Window
	local function run_console()
		if console_open then return end
		console_open = true

		local w = TextWindow.new("Console")

		-- save original logger functions
		local orig_print = print

		-- define new logger functions that append text to the window
		function print(...)
			local arg = {...}
			local n = #arg
			w:append(date() .. " ")
			for i=1, n do
				if i > 1 then w:append("\t") end
				w:append(tostring(arg[i]))
			end
			w:append("\n")
		end

		-- when the window gets closed restore the original logger functions
		local function at_close()
			print = old_print

			console_open = false
		end

		w:set_atclose(at_close)
		print("Console opened")
	end

	function ref_manual()
		browser_open_url("https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html")
	end

	function wiki_page()
		browser_open_url("https://gitlab.com/wireshark/wireshark/-/wikis/Lua")
	end

	register_menu("Lua/Evaluate", evaluate_lua, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Console", run_console, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Manual", ref_manual, MENU_TOOLS_UNSORTED)
	register_menu("Lua/Wiki", wiki_page, MENU_TOOLS_UNSORTED)
end
