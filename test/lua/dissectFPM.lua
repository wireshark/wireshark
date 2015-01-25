----------------------------------------
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, Hadriel Kaplan
-- This code is in the Public Domain, or the BSD (3 clause) license
-- if Public Domain does not apply in your country.
--
-- Version: 1.0
--
------------------------------------------
--[[
    This code is a plugin for Wireshark, to dissect Quagga FPM Netlink
    protocol messages over TCP.

    This script is used for testing, so it does some odd things:
    * it dissects the FPM in two ways, controlled by a pref setting:
        1) using the desegment_offset/desegment_len method
        2) using the dissect_tcp_pdus() method
    * it removes any existing FPM dissector; there isn't one right now
      but there likely will be in the future.

    Wireshark has a "Netlink" protocol dissector, but it currently expects
    to be running on a Linux cooked-mode SLL header and link type. That's
    because Netlink has traditionally been used between the Linux kernel
    and user-space apps. But the open-source Quagga, zebra, and the
    commercial ZebOS routing products also send Netlink messages over TCP
    to other processes or even outside the box, to a "Forwarding Plane Manager"
    (FPM) that controls forwarding-plane devices (typically hardware).

    The Netlink message is encapsulated within an FPM header, which identifies
    an FPM message version (currently 1), the type of message it contains
    (namely a Netlink message), and its length.

    So we have:
    struct fpm_msg_hdr_t
    {
        uint8_t  version;
        uint8_t  msg_type;
        uint16_t msg_len;
    }
    followed by a Netlink message.
]]----------------------------------------


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 2620,
    max_msg_len  = 4096,
    desegment    = true, -- whether to TCP desegement or not
    dissect_tcp  = false, -- whether to use the dissect_tcp_pdus method or not
    subdissect   = true, -- whether to call sub-dissector or not
    subdiss_type = wtap.NETLINK, -- the encap we get the subdissector for
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()


----------------------------------------
-- creates a Proto object, but doesn't register it yet
local fpmProto = Proto("fpm", "FPM Header")


----------------------------------------
-- a function to convert tables of enumerated types to valstring tables
-- i.e., from { "name" = number } to { number = "name" }
local function makeValString(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local MsgType = {
    NONE     = 0,
    NETLINK  = 1,
}
local msgtype_valstr = makeValString(MsgType)


----------------------------------------
-- a table of all of our Protocol's fields
local hdr_fields =
{
    version   = ProtoField.uint8 ("fpm.version", "Version", base.DEC),
    msg_type  = ProtoField.uint8 ("fpm.type", "Type", base.DEC, msgtype_valstr),
    msg_len   = ProtoField.uint16("fpm.length", "Length", base.DEC),
}

-- create a flat array table of the above that can be registered
local pfields = {}

-- recursive function to flatten the table into pfields
local function flattenTable(tbl)
    for k,v in pairs(tbl) do
        if type(v) == 'table' then
            flattenTable(v)
        else
            pfields[#pfields+1] = v
        end
    end
end
-- call it
flattenTable(hdr_fields)

-- register them
fpmProto.fields = pfields

dprint2("fpmProto ProtoFields registered")


----------------------------------------
-- some forward "declarations" of helper functions we use in the dissector
local createSLL

-- due to a bug in wireshark, we need to keep newly created tvb's for longer
-- than the duration of the dissect function
local tvbs = {}

function fpmProto.init()
    tvbs = {}
end


local FPM_MSG_HDR_LEN = 4

----------------------------------------
-- the following function is used for the new dissect_tcp_pdus method
-- this one returns the length of the full message
local function get_fpm_length(tvbuf, pktinfo, offset)
    dprint2("FPM get_fpm_length function called")
    local lengthVal = tvbuf:range(offset + 2, 2):uint()

    if lengthVal > default_settings.max_msg_len then
        -- too many bytes, invalid message
        dprint("FPM message length is too long: ", lengthVal)
        lengthVal = tvbuf:len()
    end

    return lengthVal
end

-- the following is the dissection function called for
-- the new dissect_tcp_pdus method
local function dissect_fpm_pdu(tvbuf, pktinfo, root)
    dprint2("FPM dissect_fpm_pdu function called")

    local lengthTvbr = tvbuf:range(2, 2)
    local lengthVal  = lengthTvbr:uint()

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("FPM")

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(fpmProto, tvbuf:range(offset, lengthVal))

    local versionTvbr = tvbuf:range(0, 1)
    local versionVal  = versionTvbr:uint()
    tree:add(hdr_fields.version, versionTvbr)

    local msgTypeTvbr = tvbuf:range(1, 1)
    local msgTypeVal  = msgTypeTvbr:uint()
    tree:add(hdr_fields.msg_type, msgTypeTvbr)

    tree:add(hdr_fields.msg_len, lengthTvbr)

    local result
    if (versionVal == 1) and (msgTypeVal == MsgType.NETLINK) then
        -- it carries a Netlink message, so we're going to create
        -- a fake Linux SLL header for the built-in Netlink dissector
        local payload = tvbuf:raw(FPM_MSG_HDR_LEN, lengthVal - FPM_MSG_HDR_LEN)
        result = createSLL(payload)
    end

    -- looks good, go dissect it
    if result then
        -- ok now the hard part - try calling a sub-dissector?
        -- only if settings/prefs told us to of course...
        if default_settings.subdissect then
            dprint2("FPM trying sub-dissector for wtap encap type:", default_settings.subdiss_type)

            -- due to a bug in wireshark, we need to keep newly created tvb's for longer
            -- than the duration of the dissect function
            tvbs[#tvbs+1] = ByteArray.new(result, true):tvb("Netlink Message")
            DissectorTable.get("wtap_encap"):try(default_settings.subdiss_type, tvbs[#tvbs], pktinfo, root)

            -- local tvb = ByteArray.new(result, true):tvb("Netlink Message")
            -- DissectorTable.get("wtap_encap"):try(default_settings.subdiss_type, tvb, pktinfo, root)
            dprint2("FPM returning from sub-dissector")
        end
    else
        dprint("FPM header not correctly dissected")
    end

    return lengthVal, 0
end


----------------------------------------
-- the following function is used for dissecting using the
-- old desegment_offset/desegment_len method
-- it's a separate function because we run over TCP and thus might
-- need to parse multiple messages in a single segment
local function dissect(tvbuf, pktinfo, root, offset, origlen)
    dprint2("FPM dissect function called")

    local pktlen = origlen - offset

    if pktlen < FPM_MSG_HDR_LEN then
        -- we need more bytes
        pktinfo.desegment_offset = offset
        pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return 0, DESEGMENT_ONE_MORE_SEGMENT
    end

    local lengthTvbr = tvbuf:range(offset + 2, 2)
    local lengthVal  = lengthTvbr:uint()

    if lengthVal > default_settings.max_msg_len then
        -- too many bytes, invalid message
        dprint("FPM message length is too long: ", lengthVal)
        return pktlen, 0
    end

    if pktlen < lengthVal then
        dprint2("Need more bytes to desegment FPM")
        pktinfo.desegment_offset = offset
        pktinfo.desegment_len = (lengthVal - pktlen)
        return 0, -(lengthVal - pktlen)
    end

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("FPM")

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(fpmProto, tvbuf:range(offset, lengthVal))

    local versionTvbr = tvbuf:range(offset, 1)
    local versionVal  = versionTvbr:uint()
    tree:add(hdr_fields.version, versionTvbr)

    local msgTypeTvbr = tvbuf:range(offset + 1, 1)
    local msgTypeVal  = msgTypeTvbr:uint()
    tree:add(hdr_fields.msg_type, msgTypeTvbr)

    tree:add(hdr_fields.msg_len, lengthTvbr)

    local result
    if (versionVal == 1) and (msgTypeVal == MsgType.NETLINK) then
        -- it carries a Netlink message, so we're going to create
        -- a fake Linux SLL header for the built-in Netlink dissector
        local payload = tvbuf:raw(offset + FPM_MSG_HDR_LEN, lengthVal - FPM_MSG_HDR_LEN)
        result = createSLL(payload)
    end

    -- looks good, go dissect it
    if result then
        -- ok now the hard part - try calling a sub-dissector?
        -- only if settings/prefs told us to of course...
        if default_settings.subdissect then
            dprint2("FPM trying sub-dissector for wtap encap type:", default_settings.subdiss_type)

            -- due to a bug in wireshark, we need to keep newly created tvb's for longer
            -- than the duration of the dissect function
            tvbs[#tvbs+1] = ByteArray.new(result, true):tvb("Netlink Message")
            DissectorTable.get("wtap_encap"):try(default_settings.subdiss_type, tvbs[#tvbs], pktinfo, root)

            -- local tvb = ByteArray.new(result, true):tvb("Netlink Message")
            -- DissectorTable.get("wtap_encap"):try(default_settings.subdiss_type, tvb, pktinfo, root)
            dprint2("FPM returning from sub-dissector")
        end
    else
        dprint("FPM header not correctly dissected")
    end

    return lengthVal, 0
end


----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "appProto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function fpmProto.dissector(tvbuf, pktinfo, root)
    dprint2("fpmProto.dissector called")

    local bytes_consumed = 0

    if default_settings.dissect_tcp then
        dprint2("using new dissect_tcp_pdus method")
        dissect_tcp_pdus(tvbuf, root, FPM_MSG_HDR_LEN, get_fpm_length, dissect_fpm_pdu, default_settings.desegment)
        bytes_consumed = tvbuf:len()
    else
        dprint2("using old desegment_offset/desegment_len method")
        -- get the length of the packet buffer (Tvb).
        local pktlen = tvbuf:len()
        local offset, bytes_needed = 0, 0

        tvbs = {}
        while bytes_consumed < pktlen do
            offset, bytes_needed = dissect(tvbuf, pktinfo, root, bytes_consumed, pktlen)
            if offset == 0 then
                if bytes_consumed > 0 then
                    return bytes_consumed
                else
                    return bytes_needed
                end
            end
            bytes_consumed = bytes_consumed + offset
        end
    end

    return bytes_consumed
end


----------------------------------------
-- we want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it
-- first remove any existing dissector for that port, if there is one
local old_dissector = DissectorTable.get("tcp.port"):get_dissector(default_settings.port)
if old_dissector then
    dprint("Retrieved existing dissector")
end

local function enableDissector()
    DissectorTable.get("tcp.port"):set(default_settings.port, fpmProto)
end
-- call it now
enableDissector()

local function disableDissector()
    if old_dissector then
        DissectorTable.get("tcp.port"):set(default_settings.port, old_dissector)
    end
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
fpmProto.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                       "Whether the FPM dissector is enabled or not")


fpmProto.prefs.desegment   = Pref.bool("Reassemble FPM messages spanning multiple TCP segments",
                                       default_settings.desegment,
                                       "Whether the FPM dissector should reassemble"..
                                       " messages spanning multiple TCP segments."..
                                       " To use this option, you must also enable"..
                                       " \"Allow subdissectors to reassemble TCP"..
                                       " streams\" in the TCP protocol settings.")

fpmProto.prefs.dissect_tcp = Pref.bool("Use dissect_tcp_pdus", default_settings.dissect_tcp,
                                       "Whether the FPM dissector should use the new" ..
                                       " dissect_tcp_pdus model or not")

fpmProto.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                       "Whether the FPM packet's content" ..
                                       " should be dissected or not")

fpmProto.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                       "The debug printing level", debug_pref_enum)

----------------------------------------
-- a function for handling prefs being changed
function fpmProto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.dissect_tcp = fpmProto.prefs.dissect_tcp

    default_settings.subdissect  = fpmProto.prefs.subdissect

    default_settings.debug_level = fpmProto.prefs.debug
    reset_debug_level()

    if default_settings.enabled ~= fpmProto.prefs.enabled then
        default_settings.enabled = fpmProto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")


----------------------------------------
-- the hatype field of the SLL must be 824 decimal, in big-endian encoding (0x0338)
local ARPHRD_NETLINK = "\003\056"
local WS_NETLINK_ROUTE = "\000\000"
local function emptyBytes(num)
    return string.rep("\000", num)
end

createSLL = function (payload)
    dprint2("FPM createSLL function called")
    local sllmsg =
    {
        emptyBytes(2),      -- Unused 2B
        ARPHRD_NETLINK,     -- netlink type
        emptyBytes(10),     -- Unused 10B
        WS_NETLINK_ROUTE,   -- Route type
        payload             -- the Netlink message
    }
    return table.concat(sllmsg)
end
