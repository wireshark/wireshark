-- pcap_file_reader.lua
--------------------------------------------------------------------------------
--[[
    This is a Wireshark Lua-based pcap capture file reader.
    Author: Hadriel Kaplan

    This "capture file" reader reads pcap files - the old style ones. Don't expect this to
    be as good as the real thing; this is a simplistic implementation to show how to
    create such file readers, and for testing purposes.

    This script requires Wireshark v1.12 or newer.
--]]
--------------------------------------------------------------------------------

-- do not modify this table
local debug = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug.LEVEL_1 to enable printing debug info
-- set it to debug.LEVEL_2 to enable really verbose printing
local DEBUG = debug.LEVEL_1


local wireshark_name = "Wireshark"
if not GUI_ENABLED then
    wireshark_name = "Tshark"
end

-- verify Wireshark is new enough
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your " .. wireshark_name .. " version (" .. get_version() .. ") is too old for this script!\n" ..
                "This script needs " .. wireshark_name .. "version 1.12 or higher.\n" )
end

-- verify we have the Struct library in wireshark
-- technically we should be able to do this with 'require', but Struct is a built-in
assert(Struct.unpack, wireshark_name .. " does not have the Struct library!")

--------------------------------------------------------------------------------
-- early definitions
-- throughout most of this file I try to pre-declare things to help ease
-- reading it and following the logic flow, but some things just have to be done
-- before others, so this sections has such things that cannot be avoided
--------------------------------------------------------------------------------

-- first some variable declarations for functions we'll define later
local parse_file_header, parse_rec_header, read_common

-- these will be set inside of parse_file_header(), but we're declaring them up here
local default_settings =
{
    debug           = DEBUG,
    corrected_magic = 0xa1b2c3d4,
    version_major   = 2,
    version_minor   = 4,
    timezone        = 0,
    sigfigs         = 0,
    read_snaplen    = 0, -- the snaplen we read from file
    snaplen         = 0, -- the snaplen we use (limited by WTAP_MAX_PACKET_SIZE)
    linktype        = -1, -- the raw linktype number in the file header
    wtap_type       = wtap_encaps.UNKNOWN, -- the mapped internal wtap number based on linktype
    endianess       = ENC_BIG_ENDIAN,
    time_precision  = wtap_filetypes.TSPREC_USEC,
    rec_hdr_len     = 16,            -- default size of record header
    rec_hdr_patt    = "I4 I4 I4 I4", -- pattern for Struct to use
    num_rec_fields  = 4,             -- number of vars in pattern
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug()
    if default_settings.debug > debug.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug > debug.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug()

--------------------------------------------------------------------------------
-- file reader handling functions for Wireshark to use
--------------------------------------------------------------------------------

----------------------------------------
-- The read_open() is called by Wireshark once per file, to see if the file is this reader's type.
-- Wireshark passes in (1) a File object and (2) CaptureInfo object to this function
-- It expects in return either nil or false to mean it's not our file type, or true if it is
-- In our case what this means is we figure out if the file has the magic header, and get the
-- endianess of the file, and the encapsulation type of its frames/records
local function read_open(file, capture)
    dprint2("read_open() called")

    local file_settings = parse_file_header(file)

    if file_settings then

        dprint2("read_open: success, file is for us")

        -- save our state
        capture.private_table = file_settings

        -- if the file is for us, we MUST set the file position cursor to
        -- where we want the first call to read() function to get it the next time
        -- for example if we checked a few records to be sure it's or type
        -- but in this simple example we only verify the file header (24 bytes)
        -- and we want the file position to remain after that header for our read()
        -- call, so we don't change it back
        --file:seek("set",position)

        -- these we can also set per record later during read operations
        capture.time_precision  = file_settings.time_precision
        capture.encap           = file_settings.wtap_type
        capture.snapshot_length = file_settings.snaplen

        return true
    end

    dprint2("read_open: file not for us")

    -- if it's not for us, wireshark will reset the file position itself

    return false
end

----------------------------------------
-- Wireshark/tshark calls read() for each frame/record in the file
-- It passes in (1) a File, (2) CaptureInfo, and (3) FrameInfo object to this function
-- It expects in return the file offset position the record starts at,
-- or nil/false if there's an error or end-of-file is reached.
-- The offset position is used later: wireshark remembers it and gives
-- it to seek_read() at various random times
local function read(file, capture, frame)
    dprint2("read() called")

    -- call our common reader function
    local position = file:seek()

    if not read_common("read", file, capture, frame) then
        -- this isnt' actually an error, because it might just mean we reached end-of-file
        -- so let's test for that (read(0) is a special case in Lua, see Lua docs)
        if file:read(0) ~= nil then
            dprint("read: failed to call read_common")
        else
            dprint2("read: reached end of file")
        end
        return false
    end

    dprint2("read: succeess")

    -- return the position we got to (or nil if we hit EOF/error)
    return position
end

----------------------------------------
-- Wireshark/tshark calls seek_read() for each frame/record in the file, at random times
-- It passes in (1) a File, (2) CaptureInfo, (3) FrameInfo object, and the offset position number
-- It expects in return true for successful parsing, or nil/false if there's an error.
local function seek_read(file, capture, frame, offset)
    dprint2("seek_read() called")

    -- first move to the right position in the file
    file:seek("set",offset)

    if not read_common("seek_read", file, capture, frame) then
        dprint("seek_read: failed to call read_common")
        return false
    end

    return true
end

----------------------------------------
-- Wireshark/tshark calls read_close() when it's closing the file completely
-- It passes in (1) a File and (2) CaptureInfo object to this function
-- this is a good opportunity to clean up any state you may have created during
-- file reading. (in our case there's no real state)
local function read_close(file, capture)
    dprint2("read_close() called")
    -- we don't really have to reset anything, because we used the
    -- capture.private_table and wireshark clears it for us after this function
    return true
end

----------------------------------------
-- An often unused function, Wireshark calls this when the sequential walk-through is over
-- (i.e., no more calls to read(), only to seek_read()).
-- It passes in (1) a File and (2) CaptureInfo object to this function
-- This gives you a chance to clean up any state you used during read() calls, but remember
-- that there will be calls to seek_read() after this (in Wireshark, though not Tshark)
local function seq_read_close(file, capture)
    dprint2("First pass of read() calls are over, but there may be seek_read() calls after this")
    return true
end

----------------------------------------
-- ok, so let's create a FileHandler object
local fh = FileHandler.new("Lua-based PCAP reader", "lua_pcap", "A Lua-based file reader for PCAP-type files","rms")

-- set above functions to the FileHandler
fh.read_open = read_open
fh.read = read
fh.seek_read = seek_read
fh.read_close = read_close
fh.seq_read_close = seq_read_close
fh.extensions = "pcap;cap" -- this is just a hint

-- and finally, register the FileHandler!
register_filehandler(fh)

dprint2("FileHandler registered")

--------------------------------------------------------------------------------
-- ok now for the boring stuff that actually does the work
--------------------------------------------------------------------------------

----------------------------------------
-- in Lua, we have access to encapsulation types in the 'wtap_encaps' table, but
-- those numbers don't actually necessarily match the numbers in pcap files
-- for the encapsulation type, because the namespace got screwed up at some
-- point in the past (blame LBL NRG, not wireshark for that)
-- but I'm not going to create the full mapping of these two namespaces
-- instead we'll just use this smaller table to map them
-- these are taken from wiretap/pcap-common.c
local pcap2wtap = {
    [0]   = wtap_encaps.NULL,
    [1]   = wtap_encaps.ETHERNET,
    [6]   = wtap_encaps.TOKEN_RING,
    [8]   = wtap_encaps.SLIP,
    [9]   = wtap_encaps.PPP,
    [101] = wtap_encaps.RAW_IP,
    [105] = wtap_encaps.IEEE_802_11,
    [127] = wtap_encaps.IEEE_802_11_RADIOTAP,
    [140] = wtap_encaps.MTP2,
    [141] = wtap_encaps.MTP3,
    [143] = wtap_encaps.DOCSIS,
    [147] = wtap_encaps.USER0,
    [148] = wtap_encaps.USER1,
    [149] = wtap_encaps.USER2,
    [150] = wtap_encaps.USER3,
    [151] = wtap_encaps.USER4,
    [152] = wtap_encaps.USER5,
    [153] = wtap_encaps.USER6,
    [154] = wtap_encaps.USER7,
    [155] = wtap_encaps.USER8,
    [156] = wtap_encaps.USER9,
    [157] = wtap_encaps.USER10,
    [158] = wtap_encaps.USER11,
    [159] = wtap_encaps.USER12,
    [160] = wtap_encaps.USER13,
    [161] = wtap_encaps.USER14,
    [162] = wtap_encaps.USER15,
    [186] = wtap_encaps.USB,
    [187] = wtap_encaps.BLUETOOTH_H4,
    [189] = wtap_encaps.USB_LINUX,
    [195] = wtap_encaps.IEEE802_15_4,
}

-- we can use the above to directly map very quickly
-- but to map it backwards we'll use this, because I'm lazy:
local function wtap2pcap(encap)
    for k,v in pairs(pcap2wtap) do
        if v == encap then
            return k
        end
    end
    return 0
end

----------------------------------------
-- here are the "structs" we're going to parse, of the various records in a pcap file
-- these pattern string gets used in calls to Struct.unpack()
--
-- we will prepend a '<' or '>' later, once we figure out what endian-ess the files are in
--
-- this is a constant for minimum we need to read before we figure out the filetype
local FILE_HDR_LEN = 24
-- a pcap file header struct
-- this is: magic, version_major, version_minor, timezone, sigfigs, snaplen, encap type
local FILE_HEADER_PATT = "I4 I2 I2 i4 I4 I4 I4"
-- it's too bad Struct doesn't have a way to get the number of vars the pattern holds
-- another thing to add to my to-do list?
local NUM_HDR_FIELDS = 7

-- these will hold the '<'/'>' prepended version of above
--local file_header, rec_header

-- snaplen/caplen can't be bigger than this
local WTAP_MAX_PACKET_SIZE = 65535

----------------------------------------
-- different pcap file types have different magic values
-- we need to know various things about them for various functions
-- in this script, so this table holds all the info
--
-- See default_settings table above for the defaults used if this table
-- doesn't override them.
--
-- Arguably, these magic types represent different "Protocols" to dissect later,
-- but this script treats them all as "pcapfile" protocol.
--
-- From this table, we'll auto-create a value-string table for file header magic field
local magic_spells =
{
    normal =
    {
        magic = 0xa1b2c3d4,
        name  = "Normal (Big-endian)",
    },
    swapped =
    {
        magic = 0xd4c3b2a1,
        name  = "Swapped Normal (Little-endian)",
        endianess = ENC_LITTLE_ENDIAN,
    },
    modified =
    {
        -- this is for a ss991029 patched format only
        magic = 0xa1b2cd34,
        name  = "Modified",
        rec_hdr_len    = 24,
        rec_hdr_patt   = "I4I4I4I4 I4 I2 I1 I1",
        num_rec_fields = 8,
    },
    swapped_modified =
    {
        -- this is for a ss991029 patched format only
        magic = 0x34cdb2a1,
        name  = "Swapped Modified",
        rec_hdr_len    = 24,
        rec_hdr_patt   = "I4I4I4I4 I4 I2 I1 I1",
        num_rec_fields = 8,
        endianess = ENC_LITTLE_ENDIAN,
    },
    nsecs =
    {
        magic = 0xa1b23c4d,
        name  = "Nanosecond",
        time_precision = wtap_filetypes.TSPREC_NSEC,
    },
    swapped_nsecs =
    {
        magic = 0x4d3cb2a1,
        name  = "Swapped Nanosecond",
        endianess      = ENC_LITTLE_ENDIAN,
        time_precision = wtap_filetypes.TSPREC_NSEC,
    },
}

-- create a magic-to-spell entry table from above magic_spells table
-- so we can find them faster during file read operations
-- we could just add them right back into spells table, but this is cleaner
local magic_values = {}
for k,t in pairs(magic_spells) do
    magic_values[t.magic] = t
end

-- the function which makes a copy of the default settings per file
local function new_settings()
    dprint2("creating new file_settings")
    local file_settings = {}
    for k,v in pairs(default_settings) do
        file_settings[k] = v
    end
    return file_settings
end

-- set the file_settings that the magic value defines in magic_values
local function set_magic_file_settings(magic)
    local t = magic_values[magic]
    if not t then
        dprint("set_magic_file_settings: did not find magic settings for:",magic)
        return false
    end

    local file_settings = new_settings()

    -- the magic_values/spells table uses the same key names, so this is easy
    for k,v in pairs(t) do
        file_settings[k] = v
    end

    -- based on endianess, set the file_header and rec_header
    -- and determine corrected_magic
    if file_settings.endianess == ENC_BIG_ENDIAN then
        file_settings.file_hdr_patt = '>' .. FILE_HEADER_PATT
        file_settings.rec_hdr_patt  = '>' .. file_settings.rec_hdr_patt
        file_settings.corrected_magic = magic
    else
        file_settings.file_hdr_patt = '<' .. FILE_HEADER_PATT
        file_settings.rec_hdr_patt  = '<' .. file_settings.rec_hdr_patt
        local m = Struct.pack(">I4", magic)
        file_settings.corrected_magic = Struct.unpack("<I4", m)
    end

    file_settings.rec_hdr_len = Struct.size(file_settings.rec_hdr_patt)

    return file_settings
end

----------------------------------------
-- internal functions declared previously
----------------------------------------

----------------------------------------
-- used by read_open(), this parses the file header
parse_file_header = function(file)
    dprint2("parse_file_header() called")

    -- by default, file:read() gets the next "string", meaning ending with a newline \n
    -- but we want raw byte reads, so tell it how many bytes to read
    local line = file:read(FILE_HDR_LEN)

    -- it's ok for us to not be able to read it, but we need to tell wireshark the
    -- file's not for us, so return false
    if not line then return false end

    dprint2("parse_file_header: got this line:\n'", Struct.tohex(line,false,":"), "'")

    -- let's peek at the magic int32, assuming it's big-endian
    local magic = Struct.unpack(">I4", line)

    local file_settings = set_magic_file_settings(magic)

    if not file_settings then
        dprint("magic was: '", magic, "', so not a known pcap file?")
        return false
    end

    -- this is: magic, version_major, version_minor, timezone, sigfigs, snaplen, encap type
    local fields = { Struct.unpack(file_settings.file_hdr_patt, line) }

    -- sanity check; also note that Struct.unpack() returns the fields plus
    -- a number of where in the line it stopped reading (i.e., the end in this case)
    -- so we got back number of fields + 1
    if #fields ~= NUM_HDR_FIELDS + 1 then
        -- this should never happen, since we already told file:read() to grab enough bytes
        dprint("parse_file_header: failed to read the file header")
        return nil
    end

    -- fields[1] is the magic, which we already parsed and saved before, but just to be sure
    -- our endianess is set right, we validate what we got is what we expect now that
    -- endianess has been corrected
    if fields[1] ~= file_settings.corrected_magic then
        dprint ("parse_file_header: endianess screwed up? Got:'", fields[1],
                "', but wanted:", file_settings.corrected_magic)
        return nil
    end

    file_settings.version_major = fields[2]
    file_settings.version_minor = fields[3]
    file_settings.timezone      = fields[4]
    file_settings.sigfigs       = fields[5]
    file_settings.read_snaplen  = fields[6]
    file_settings.linktype      = fields[7]

    -- wireshark only supports version 2.0 and later
    if fields[2] < 2 then
        dprint("got version =",VERSION_MAJOR,"but only version 2 or greater supported")
        return false
    end

    -- convert pcap file interface type to wtap number type
    file_settings.wtap_type = pcap2wtap[file_settings.linktype]
    if not file_settings.wtap_type then
        dprint("file nettype", file_settings.linktype,
               "couldn't be mapped to wireshark wtap type")
        return false
    end

    file_settings.snaplen = file_settings.read_snaplen
    if file_settings.snaplen > WTAP_MAX_PACKET_SIZE then
        file_settings.snaplen = WTAP_MAX_PACKET_SIZE
    end

    dprint2("read_file_header: got magic='", magic,
            "', major version='", file_settings.version_major,
            "', minor='", file_settings.version_minor,
            "', timezone='", file_settings.timezone,
            "', sigfigs='", file_settings.sigfigs,
            "', read_snaplen='", file_settings.read_snaplen,
            "', snaplen='", file_settings.snaplen,
            "', nettype ='", file_settings.linktype,
            "', wtap ='", file_settings.wtap_type)

    --ok, it's a pcap file
    dprint2("parse_file_header: success")
    return file_settings
end

----------------------------------------
-- this is used by both read() and seek_read()
-- the calling function to this should have already set the file position correctly
read_common = function(funcname, file, capture, frame)
    dprint2(funcname,": read_common() called")

    -- get the state info
    local file_settings = capture.private_table

    -- first parse the record header, which will set the FrameInfo fields
    if not parse_rec_header(funcname, file, file_settings, frame) then
        dprint2(funcname, ": read_common: hit end of file or error")
        return false
    end

    frame.encap = file_settings.wtap_type

    -- now we need to get the packet bytes from the file record into the frame...
    -- we *could* read them into a string using file:read(numbytes), and then
    -- set them to frame.data so that wireshark gets it...
    -- but that would mean the packet's string would be copied into Lua
    -- and then sent right back into wireshark, which is gonna slow things
    -- down; instead FrameInfo has a read_data() method, which makes
    -- wireshark read directly from the file into the frame buffer, so we use that
    if not frame:read_data(file, frame.captured_length) then
        dprint(funcname, ": read_common: failed to read data from file into buffer")
        return false
    end

    return true
end

----------------------------------------
-- the function to parse individual records
parse_rec_header = function(funcname, file, file_settings, frame)
    dprint2(funcname,": parse_rec_header() called")

    local line = file:read(file_settings.rec_hdr_len)

    -- it's ok for us to not be able to read it, if it's end of file
    if not line then return false end

    -- this is: time_sec, time_usec, capture_len, original_len
    local fields = { Struct.unpack(file_settings.rec_hdr_patt, line) }

    -- sanity check; also note that Struct.unpack() returns the fields plus
    -- a number of where in the line it stopped reading (i.e., the end in this case)
    -- so we got back number of fields + 1
    if #fields ~= file_settings.num_rec_fields + 1 then
        dprint(funcname, ": parse_rec_header: failed to read the record header, got:",
               #fields, ", expected:", file_settings.num_rec_fields)
        return nil
    end

    local nsecs = fields[2]

    if file_settings.time_precision == wtap_filetypes.TSPREC_USEC then
        nsecs = nsecs * 1000
    elseif file_settings.time_precision == wtap_filetypes.TSPREC_MSEC then
        nsecs = nsecs * 1000000
    end

    frame.time = NSTime(fields[1], nsecs)

    local caplen, origlen = fields[3], fields[4]

    -- sanity check, verify captured length isn't more than original length
    if caplen > origlen then
        dprint("captured length of", caplen, "is bigger than original length of", origlen)
        -- swap them, a cool Lua ability
        caplen, origlen = origlen, caplen
    end

    if caplen > WTAP_MAX_PACKET_SIZE then
        dprint("Got a captured_length of", caplen, "which is too big")
        caplen = WTAP_MAX_PACKET_SIZE
    end

    frame.rec_type = wtap_rec_types.PACKET

    frame.captured_length = caplen
    frame.original_length = origlen

    frame.flags = wtap_presence_flags.TS + wtap_presence_flags.CAP_LEN -- for timestamp|cap_len

    dprint2(funcname,": parse_rec_header() returning")
    return true
end



--------------------------------------------------------------------------------
-- file writer handling functions for Wireshark to use
--------------------------------------------------------------------------------

-- file encaps we can handle writing
local canwrite = {
    [ wtap_encaps.NULL ]        = true,
    [ wtap_encaps.ETHERNET ]    = true,
    [ wtap_encaps.PPP ]         = true,
    [ wtap_encaps.RAW_IP ]      = true,
    [ wtap_encaps.IEEE_802_11 ] = true,
    [ wtap_encaps.MTP2 ]        = true,
    [ wtap_encaps.MTP3 ]        = true,
    -- etc., etc.
}

-- we can't reuse the variables we used in the reader, because this script might be used to both
-- open a file for reading and write it out, at the same time, so we cerate another file_settings
-- instance.
-- set the file_settings for the little-endian version in magic_spells
local function create_writer_file_settings()
    dprint2("create_writer_file_settings called")
    local t = magic_spells.swapped

    local file_settings = new_settings()

    -- the magic_values/spells table uses the same key names, so this is easy
    for k,v in pairs(t) do
        file_settings[k] = v
    end

    -- based on endianess, set the file_header and rec_header
    -- and determine corrected_magic
    if file_settings.endianess == ENC_BIG_ENDIAN then
        file_settings.file_hdr_patt = '>' .. FILE_HEADER_PATT
        file_settings.rec_hdr_patt  = '>' .. file_settings.rec_hdr_patt
        file_settings.corrected_magic = file_settings.magic
    else
        file_settings.file_hdr_patt = '<' .. FILE_HEADER_PATT
        file_settings.rec_hdr_patt  = '<' .. file_settings.rec_hdr_patt
        local m = Struct.pack(">I4", file_settings.magic)
        file_settings.corrected_magic = Struct.unpack("<I4", m)
    end

    file_settings.rec_hdr_len = Struct.size(file_settings.rec_hdr_patt)

    return file_settings
end

----------------------------------------
-- The can_write_encap() function is called by Wireshark when it wants to write out a file,
-- and needs to see if this file writer can handle the packet types in the window.
-- We need to return true if we can handle it, else false
local function can_write_encap(encap)
    dprint2("can_write_encap() called with encap=",encap)
    return canwrite[encap] or false
end

local function write_open(file, capture)
    dprint2("write_open() called")

    local file_settings = create_writer_file_settings()

    -- write out file header
    local hdr = Struct.pack(file_settings.file_hdr_patt,
                            file_settings.corrected_magic,
                            file_settings.version_major,
                            file_settings.version_minor,
                            file_settings.timezone,
                            file_settings.sigfigs,
                            capture.snapshot_length,
                            wtap2pcap(capture.encap))

    if not hdr then
        dprint("write_open: error generating file header")
        return false
    end

    dprint2("write_open generating:", Struct.tohex(hdr))

    if not file:write(hdr) then
        dprint("write_open: error writing file header to file")
        return false
    end

    -- save settings
    capture.private_table = file_settings

    return true
end

local function write(file, capture, frame)
    dprint2("write() called")

    -- get file settings
    local file_settings = capture.private_table
    if not file_settings then
        dprint("write() failed to get private table file settings")
        return false
    end

    -- write out record header: time_sec, time_usec, capture_len, original_len

    -- first get times
    local nstime = frame.time

    -- pcap format is in usecs, but wireshark's internal is nsecs
    local nsecs = nstime.nsecs

    if file_settings.time_precision == wtap_filetypes.TSPREC_USEC then
        nsecs = nsecs / 1000
    elseif file_settings.time_precision == wtap_filetypes.TSPREC_MSEC then
        nsecs = nsecs / 1000000
    end

    local hdr = Struct.pack(file_settings.rec_hdr_patt,
                            nstime.secs,
                            nsecs,
                            frame.captured_length,
                            frame.original_length)

    if not hdr then
        dprint("write: error generating record header")
        return false
    end

    if not file:write(hdr) then
        dprint("write: error writing record header to file")
        return false
    end

    -- we could write the packet data the same way, by getting frame.data and writing it out
    -- but we can avoid copying those bytes into Lua by using the write_data() function
    if not frame:write_data(file) then
        dprint("write: error writing record data to file")
        return false
    end

    return true
end

local function write_close(file, capture)
    dprint2("write_close() called")
    dprint2("Good night, and good luck")
    return true
end

-- ok, so let's create another FileHandler object
local fh2 = FileHandler.new("Lua-based PCAP writer", "lua_pcap2", "A Lua-based file writer for PCAP-type files","wms")

-- set above functions to the FileHandler
fh2.can_write_encap = can_write_encap
fh2.write_open = write_open
fh2.write = write
fh2.write_close = write_close
fh2.extensions = "pcap;cap" -- this is just a hint

-- and finally, register the FileHandler!
register_filehandler(fh2)

dprint2("Second FileHandler registered")
