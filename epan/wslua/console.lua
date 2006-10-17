-- A console to execute commands in lua
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