-- browser_sslkeylog.lua
--
-- Run a browser with SSLKEYLOG set.
--
-- (c) 2021 Gerald Combs <gerald@wireshark.org>
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- SPDX-License-Identifier: GPL-2.0-or-later

-- To do:
-- - Support more browsers.
-- - Add stat() to the API and use it.
-- - Add OS detection to the API and use it.

if not gui_enabled() then return end

do
	local function is_file(path)
		f = io.open(path, 'rb')
		if f ~= nil then
			io.close(f)
			return true
		end
		return false
	end

	local function show_skl_window()
		local prefs_ok = false

		local skl_win = TextWindow.new("Launch with SSLKEYLOG")
		skl_win:set_editable(false)
		skl_win:set(
			"This will run either Chrome or Firefox with the SSLKEYLOG environment variable set to the file specified by the TLS protocol (Pre)-Master-Secret log filename preference."
		)

		local chrome_cmd = nil
		local function launch_chrome()
			os.execute(chrome_cmd)
			skl_win:close()
		end

		local firefox_cmd = nil
		local function launch_firefox()
			os.execute(firefox_cmd)
			skl_win:close()
		end

		-- Check our preferences.
		local keylog_path = get_preference("tls.keylog_file")
		if (keylog_path == nil or string.len(keylog_path) < 2) then -- "/x" is the minimum usable path.
			skl_win:append(
				"\n\n" ..
				"Your key log preference isn't set. Please go to \"Preferences → Protocols → TLS → (Pre)-Master-Secret log filename\" and add a filename."
			)
		else
			skl_win:append(
				"\n\n" ..
				"TLS keys will be logged to " .. keylog_path .. "."
			)
			prefs_ok = true
		end

		-- Look for browsers.
		local win_programfiles = os.getenv("ProgramFiles")
		local has_applications = Dir.exists("/Applications")
		local has_usr_bin = Dir.exists("/usr/bin")
		if (win_programfiles ~= nil and string.len(win_programfiles) > 3) then -- "C:\x"
			local path_prefixes = { win_programfiles }
			local chrome_suf = "\\Google\\Chrome\\Application\\chrome.exe"
			local firefox_suf = "\\Mozilla Firefox\\firefox.exe"
			local win_localappdata = os.getenv("LocalAppData")
			if (win_localappdata ~= nil and string.len(win_localappdata) > 3) then
				table.insert(path_prefixes, win_localappdata)
			end
			local win_programfiles_x86 = os.getenv("ProgramFiles(x86)")
			if (win_programfiles_x86 ~= nil and string.len(win_programfiles_x86) > 3) then
				table.insert(path_prefixes, win_programfiles_x86)
			end
			for _, path_prefix in ipairs(path_prefixes) do
				chrome_path = path_prefix .. chrome_suf
				if (is_file(chrome_path)) then
					chrome_cmd = "cmd /c \"set SSLKEYLOGFILE=" .. keylog_path .. " && cmd /c ^\"" .. chrome_path .. "^\"\""
					break
				end
			end
			for _, path_prefix in ipairs(path_prefixes) do
				firefox_path = path_prefix .. firefox_suf
				if (is_file(firefox_path)) then
					firefox_cmd = "cmd /c \"set SSLKEYLOGFILE=" .. keylog_path .. " && cmd /c ^\"" .. firefox_path .. "^\"\""
					break
				end
			end
		elseif (has_applications) then
			if (Dir.exists("/Applications/Google Chrome.app")) then
				chrome_cmd = "open --env=SSLKEYLOGFILE=\"" .. keylog_path .. "\" '/Applications/Google Chrome.app'"
			end
			if (Dir.exists("/Applications/Firefox.app")) then
				firefox_cmd = "open --env=SSLKEYLOGFILE=\"" .. keylog_path .. "\" '/Applications/Firefox.app'"
			end
		elseif (has_usr_bin) then
			local path_prefixes = { "/usr/bin/", "/usr/local/bin/" }
			for _, path_prefix in ipairs(path_prefixes) do
				chrome_path = path_prefix .. "chrome"
				if (is_file(chrome_path)) then
					chrome_cmd = "SSLKEYLOGFILE=\"" .. keylog_path .. "\" " .. chrome_path
					break
				end
			end
			for _, path_prefix in ipairs(path_prefixes) do
				firefox_path = path_prefix .. "firefox"
				if (is_file(firefox_path)) then
					firefox_cmd = "SSLKEYLOGFILE=\"" .. keylog_path .. "\" " .. firefox_path
					break
				end
			end
		end

		if (chrome_cmd == nil and firefox_cmd == nil) then
			skl_win:append(
				"\n\n" ..
				"Unable to find Chrome or Firefox."
			)
		elseif (prefs_ok) then
			skl_win:append(
				"\n\n" ..
				"If your desired browser is currently running, close it first before launching it below."
			)
			if (chrome_cmd) then
				skl_win:add_button("Launch Chrome", launch_chrome)
			end

			if (firefox_cmd) then
				skl_win:add_button("Launch Firefox", launch_firefox)
			end
		end

	end

	register_menu("Lua Scripts/Launch with SSLKEYLOG", show_skl_window, MENU_TOOLS_UNSORTED)

	-- menu_pfx = "Lua Scripts/Launch with SSLKEYLOG/"
	-- register_menu(menu_pfx .. "Chrome",run_chrome,MENU_TOOLS_UNSORTED)
	-- register_menu(menu_pfx .. "Firefox",run_firefox,MENU_TOOLS_UNSORTED)
end
