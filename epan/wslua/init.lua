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


function typeof(obj)
    local mt = getmetatable(obj)

    if type(obj) == "table" then
        return mt and mt.__typeof or obj.__typeof or type(obj)
    else
        return mt and mt.__typeof or type(obj)
    end
end

-- the following function checks if a file exists
-- since 1.11.3
function file_exists(name)
   local f = io.open(name,"r")
   if f ~= nil then io.close(f) return true else return false end
end

-- the following function prepends the given directory name to
-- the package.path, so that a 'require "foo"' will work if 'foo'
-- is in the directory name given to this function. For example,
-- if your Lua file will do a 'require "foo"' and the foo.lua
-- file is in a local directory (local to your script) named 'bar',
-- then call this function before doing your 'require', by doing
--     package.prepend_path("bar")
-- and that will let Wireshark's Lua find the file "bar/foo.lua"
-- when you later do 'require "foo"'
--
-- Because this function resides here in init.lua, it does not
-- have the same environment as your script, so it has to get it
-- using the debug library, which is why the code appears so
-- cumbersome.
--
-- since 1.11.3
function package.prepend_path(name)
    -- get the function calling this package.prepend_path function
    local dt = debug.getinfo(2, "f")
    if not dt then
        error("could not retrieve debug info table")
    end
    -- get its upvalue
    local _, val = debug.getupvalue(dt.func, 1)
    if not val or type(val) ~= 'table' then
        error("No calling function upvalue or it is not a table")
    end
    -- get the __DIR__ field in its upvalue table
    local dir = val["__DIR__"]
    -- get the platform-specific directory separator character
    local sep = package.config:sub(1,1)
    -- prepend the dir and given name to path
    if dir and dir:len() > 0 then
        package.path = dir .. sep .. name .. sep .. "?.lua;" .. package.path
    end
    -- also prepend just the name as a directory
    package.path = name .. sep .. "?.lua;" .. package.path
end

-- for backward compatibility
wtap = wtap_encaps

--
-- Generate the wtap_filetypes items for file types, for backwards
-- compatibility.
-- We no longer have WTAP_FILE_TYPE_SUBTYPE_ #defines;
-- built-in file types are registered the same way that
-- plugin file types are registered.
--
-- New code should use wtap_name_to_file_type_subtype to
-- look up file types by name.
--
wtap_filetypes = get_wtap_filetypes()

-- Old / deprecated menu groups. These shoudn't be used in new code.
MENU_ANALYZE_UNSORTED = MENU_PACKET_ANALYZE_UNSORTED
MENU_ANALYZE_CONVERSATION = MENU_ANALYZE_CONVERSATION_FILTER
MENU_STAT_CONVERSATION = MENU_STAT_CONVERSATION_LIST
MENU_STAT_ENDPOINT = MENU_STAT_ENDPOINT_LIST
MENU_STAT_RESPONSE = MENU_STAT_RESPONSE_TIME
MENU_STAT_UNSORTED = MENU_PACKET_STAT_UNSORTED

-- the possible values for Pinfo's p2p_dir attribute
P2P_DIR_UNKNOWN = -1
P2P_DIR_SENT    =  0
P2P_DIR_RECV    =  1


-- other useful constants
-- DATA_DIR and USER_DIR have a trailing directory separator.
GUI_ENABLED = gui_enabled()
DATA_DIR = Dir.global_config_path()..package.config:sub(1,1)
USER_DIR = Dir.personal_config_path()..package.config:sub(1,1)

-- deprecated function names
datafile_path = Dir.global_config_path
persconffile_path = Dir.personal_config_path


if not running_superuser or run_user_scripts_when_superuser then
    dofile(DATA_DIR.."console.lua")
end
--dofile(DATA_DIR.."dtd_gen.lua")
