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

-- If set and Wireshark was started as (setuid) root, then the user
-- will not be able to execute custom Lua scripts from the personal
-- configuration directory, the -Xlua_script command line option or
-- the Lua Evaluate menu option in the GUI.
run_user_scripts_when_superuser = true


function typeof(obj)
    local mt = getmetatable(obj)
    return mt and mt.__typeof or obj.__typeof or type(obj)
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

%WTAP_ENCAPS%

--
-- This pulls in the WTAP_TSPREC_ values that are included in
-- wtap_filetypes for backwards compatibility.
--
%WTAP_FILETYPES%

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
-- "UNKNOWN" is a special case; it has no name.
--
wtap_filetypes["UNKNOWN"] = 0
for filetype = 1, wtap_get_num_file_types_subtypes() - 1 do
    local typename = wtap_file_type_subtype_name(filetype)
    --
    -- In most cases, the old #define was just a capitalized
    -- version of the file type name.
    --
    -- We process the exceptions here.
    --
    if typename == "nsecpcap" then
        wtap_filetypes["PCAP_NSEC"] = filetype
    elseif typename == "aixpcap" then
        wtap_filetypes["PCAP_AIX"] = filetype
    elseif typename == "modpcap" then
        wtap_filetypes["PCAP_SS991029"] = filetype
    elseif typename == "nokiapcap" then
        wtap_filetypes["PCAP_NOKIA"] = filetype
    elseif typename == "rh6_1pcap" then
        wtap_filetypes["PCAP_SS990417"] = filetype
    elseif typename == "suse6_3pcap" then
        wtap_filetypes["PCAP_SS990915"] = filetype
    elseif typename == "iptrace_1" then
        wtap_filetypes["IPTRACE_1_0"] = filetype
    elseif typename == "iptrace_2" then
        wtap_filetypes["IPTRACE_2_0"] = filetype
    elseif typename == "dct2000" then
        wtap_filetypes["CATAPULT_DCT2000"] = filetype
    elseif typename == "netxray1" then
        wtap_filetypes["NETXRAY_OLD"] = filetype
    elseif typename == "netxray2" then
        -- This is correct; the #define was wrong
        wtap_filetypes["NETXRAY_1_0"] = filetype
    elseif typename == "etherwatch" then
        wtap_filetypes["DBS_ETHERWATCH"] = filetype
    elseif typename == "iseries_ascii" then
        wtap_filetypes["ISERIES"] = filetype
    elseif typename == "iseries_unicode" then
        wtap_filetypes["ISERIES_UNICODE"] = filetype
    elseif typename == "netmon1" then
        wtap_filetypes["NETMON_1_x"] = filetype
    elseif typename == "netmon2" then
        wtap_filetypes["NETMON_2_x"] = filetype
    elseif typename == "ngsniffer" then
        wtap_filetypes["NGSNIFFER_UNCOMPRESSED"] = filetype
    elseif typename == "ngsniffer_comp" then
        wtap_filetypes["NGSNIFFER_COMPRESSED"] = filetype
    elseif typename == "ngwsniffer_1_1" then
        wtap_filetypes["NETXRAY_1_1"] = filetype
    elseif typename == "ngwsniffer_2_0" then
        wtap_filetypes["NETXRAY_2_00x"] = filetype
    elseif typename == "niobserver" then
        wtap_filetypes["NETWORK_INSTRUMENTS"] = filetype
    elseif typename == "pppd" then
        wtap_filetypes["PPPDUMP"] = filetype
    elseif typename == "tcpiptrace" then
        wtap_filetypes["VMS"] = filetype
    elseif typename == "rf5" then
        wtap_filetypes["K12"] = filetype
    elseif typename == "visual" then
        wtap_filetypes["VISUAL_NETWORKS"] = filetype
    elseif typename == "peekclassic56" then
        wtap_filetypes["PEEKCLASSIC_V56"] = filetype
    elseif typename == "peekclassic7" then
        wtap_filetypes["PEEKCLASSIC_V7"] = filetype
    elseif typename == "pklg" then
        wtap_filetypes["PACKETLOGGER"] = filetype
    elseif typename == "dsna" then
        wtap_filetypes["DAINTREE_SNA"] = filetype
    elseif typename == "nstrace10" then
        wtap_filetypes["NETSCALER_1_0"] = filetype
    elseif typename == "nstrace20" then
        wtap_filetypes["NETSCALER_2_0"] = filetype
    elseif typename == "nstrace30" then
        wtap_filetypes["NETSCALER_3_0"] = filetype
    elseif typename == "nstrace35" then
        wtap_filetypes["NETSCALER_3_5"] = filetype
    elseif typename == "jpeg" then
        wtap_filetypes["JPEG_JFIF"] = filetype
    elseif typename == "mp2t" then
        wtap_filetypes["MPEG_2_TS"] = filetype
    elseif typename == "vwr80211" then
        wtap_filetypes["VWR_80211"] = filetype
    elseif typename == "vwreth" then
        wtap_filetypes["VWR_ETH"] = filetype
    elseif typename == "stanag4607" then
        wtap_filetypes["STANAG_4607"] = filetype
    elseif typename == "logcat-brief" then
        wtap_filetypes["LOGCAT_BRIEF"] = filetype
    elseif typename == "logcat-process" then
        wtap_filetypes["LOGCAT_PROCESS"] = filetype
    elseif typename == "logcat-tag" then
        wtap_filetypes["LOGCAT_TAG"] = filetype
    elseif typename == "logcat-thread" then
        wtap_filetypes["LOGCAT_THREAD"] = filetype
    elseif typename == "logcat-time" then
        wtap_filetypes["LOGCAT_TIME"] = filetype
    elseif typename == "logcat-threadtime" then
        wtap_filetypes["LOGCAT_THREADTIME"] = filetype
    elseif typename == "logcat-long" then
        wtap_filetypes["LOGCAT_LONG"] = filetype
    elseif typename == "colasoft-pb" then
        wtap_filetypes["PACKET_BUILDER"] = filetype
    elseif typename == "3gpp32423" then
        wtap_filetypes["NETTRACE_3GPP_32_423"] = filetype
    elseif typename == "3gpp_log" then
        wtap_filetypes["LOG_3GPP"] = filetype
    elseif typename == "jpeg" then
        wtap_filetypes["JPEG_JFIF"] = filetype
    else
        wtap_filetypes[string.upper(typename)] = filetype
    end
end

%WTAP_TSPRECS%

%WTAP_COMMENTTYPES%

%FT_TYPES%

-- the following table is since 2.0
%FT_FRAME_TYPES%

-- the following table is since 1.12
%WTAP_REC_TYPES%

-- the following table is since 1.11.3
%WTAP_PRESENCE_FLAGS%

%BASES%

%ENCODINGS%

%EXPERT%

-- the following table is since 1.11.3
%EXPERT_TABLE%

%MENU_GROUPS%

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
