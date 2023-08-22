-- init.lua
--
-- initialize wireshark's lua
--
--  This file is going to be executed before any other lua script.
--  It can be used to load libraries, disable functions and more.
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- SPDX-License-Identifier: GPL-2.0-or-later

-- Set enable_lua to false to disable Lua support.
enable_lua = true

if not enable_lua then
    return
end

-- If false and Wireshark was started as (setuid) root, then the user
-- will not be able to execute custom Lua scripts from the personal
-- configuration directory, the -Xlua_script command line option or
-- the Lua Evaluate menu option in the GUI.
-- Note: Not checked on Windows. running_superuser is always false.
run_user_scripts_when_superuser = true
