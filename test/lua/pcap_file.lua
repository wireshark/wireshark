-- pcap_file_reader.lua
--------------------------------------------------------------------------------
--[[
    This is a Wireshark Lua-based pcap capture file reader.
    Author: Hadriel Kaplan

    This "capture file" reader reads pcap files - the old style ones. Don't expect this to
    be as good as the real thing; this is a simplistic implementation to show how to
    create such file readers, and for testing purposes.

    This script requires Wireshark v1.11.3 or newer.
--]]
--------------------------------------------------------------------------------

local wireshark_name = "Wireshark"
if not GUI_ENABLED then
    wireshark_name = "Tshark"
end

-- verify Wireshark is new enough
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your " .. wireshark_name .. " version (" .. get_version() .. ") is too old for this script!\n" ..
                "This script needs " .. wireshark_name .. "version 1.11.3 or higher.\n" )
end

-- verify we have the Struct library in wireshark
-- technically we should be able to do this with 'require', but Struct is a built-in
assert(Struct.unpack, wireshark_name .. " does not have the Struct library!")

-- debug printer, set DEBUG to true to enable printing debug info
-- set DEBUG2 to true to enable really verbose printing
local DEBUG, DEBUG2 = false, false

local dprint = function() end
local dprint2 = function() end
if DEBUG or DEBUG2 then
    dprint = function(...)
        print(table.concat({"Lua:", ...}," "))
    end

    if DEBUG2 then
        dprint2 = dprint
    end
end

----------------------------------------
-- to make it easier to read this file, we'll define some of the functions
-- later on, but we need them earlier, so we "declare" them here
local parse_file_header, parse_rec_header, read_common


-- these will be set inside of parse_file_header(), but we're declaring them up here
local VERSION_MAJOR = 2
local VERSION_MINOR = 4
local TIMEZONE = 0
local SIGFIGS = 0
local SNAPLEN = 0
local ENCAP_TYPE = wtap.UNKNOWN

--------------------------------------------------------------------------------
-- file reader handling functions for Wireshark to use
--------------------------------------------------------------------------------

----------------------------------------
-- The read_open() is called by Wireshark once per file, to see if the file is this reader's type.
-- Wireshark passes in a File object to this function
-- It expects in return either nil or false to mean it's not our file type, or true if it is
-- In our case what this means is we figure out if the file has the magic header, and get the
-- endianess of the file, and the encapsulation type of its frames/records
-- Since Wireshark uses the file cursor position for future reading of this file, we also have to seek back to the beginning
-- so that our normal read() function works correctly.
local function read_open(file, capture)
    dprint2("read_open() called")

    -- save current position to return later
    local position = file:seek()

    if parse_file_header(file) then

        dprint2("read_open: success, file is for us")

        -- if the file is for us, we MUST set the file position cursor to
        -- where we want the first call to read() function to get it the next time
        -- for example if we checked a few records to be sure it's or type
        -- but in this simple example we only verify the file header (24 bytes)
        -- and we want the file position to remain after that header for our read()
        -- call, so we don't change it back
        --file:seek("set",position)

        -- these we can also set per record later during read operations
        capture.time_precision = wtap_filetypes.TSPREC_USEC  -- for microsecond precision
        capture.encap = ENCAP_TYPE -- this was updated by parse_file_header()
        capture.snapshot_length = SNAPLEN  -- also updated by parse_file_header()

        return true
    end

    dprint2("read_open: file not for us")

    -- if it's not for us, wireshark will reset the file position itself
    -- but we might as well do it too, in case that behavior ever changes
    file:seek("set",position)

    return false
end

----------------------------------------
-- Wireshark/tshark calls read() for each frame/record in the file
-- It passes in a File object and FrameInfo object to this function
-- It expects in return the file offset position the record starts at,
-- or nil/false if there's an error or end-of-file is reached.
-- The offset position is used later: wireshark remembers it and gives
-- it to seek_read() at various random times
local function read(file, frame)
    dprint2("read() called")

    -- call our common reader function
    local position = file:seek()

    if not read_common("read", file, frame) then
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
-- It passes in to this function a File object, FrameInfo object, and the offset position number
-- It expects in return true for successful parsing, or nil/false if there's an error.
local function seek_read(file, frame, offset)
    dprint2("seek_read() called")

    -- first move to the right position in the file
    file:seek("set",offset)

    if not read_common("seek_read", file, frame) then
        dprint("seek_read: failed to call read_common")
        return false
    end

    return true
end

----------------------------------------
-- Wireshark/tshark calls read_close() when it's closing the file completely
-- this is a good opportunity to clean up any state you may have created during
-- file reading. (in our case there's no real state)
local function read_close(file)
    dprint2("read_close() called")
    -- we don't really have to reset these, but just to show what you might do in this function...
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    TIMEZONE = 0
    SIGFIGS = 0
    SNAPLEN = 0
    ENCAP_TYPE = wtap.UNKNOWN
    return true
end

----------------------------------------
-- An often unused function, Wireshark calls this when the sequential walk-through is over
-- (i.e., no more calls to read(), only to seek_read()).
-- This gives you a chance to clean up any state you used during read() calls, but remember
-- that there will be calls to seek_read() after this (in Wireshark, though not Tshark)
local function seq_read_close(file)
    dprint2("First pass of read() calls are over, but there may be seek_read() calls after this")
    return true
end

----------------------------------------
-- ok, so let's create a FileHandler object
local fh = FileHandler.new("Lua-based PCAP reader", "lua_pcap", "A Lua-based file reader for PCAP-type files","rs")

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
-- the pcap magic field: 0xA1B2C3D4, of both endianess
local MAGIC         = 0xa1b2c3d4
local SWAPPED_MAGIC = 0xd4c3b2a1

-- here are the "structs" we're going to parse, of the various records in a pcap file
-- these pattern string gets used in calls to Struct.unpack()
--
-- we will prepend a '<' or '>' later, once we figure out what endian-ess the files are in
--
-- a pcap file header struct
-- this is: magic, version_major, version_minor, timezone, sigfigs, snaplen, encap type
local FILE_HEADER = "I4 I2 I2 i4 I4 I4 I4"
local FILE_HDR_LEN = Struct.size(FILE_HEADER)

-- a pcap record header struct
-- this is: time_sec, time_usec, capture_len, original_len
local REC_HEADER = "I4 I4 I4 I4"
local REC_HDR_LEN  = Struct.size(REC_HEADER)
local NUM_REC_FIELDS = 4

-- these will hold the '<'/'>' prepended version of above
local file_header, rec_header

-- snaplen/caplen can't be bigger than this
local WTAP_MAX_PACKET_SIZE = 65535

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

    -- let's peek at the magic int32, assuming it's little-endian
    local magic = Struct.unpack("<I4", line)

    if magic == MAGIC then
        dprint2("file is little-endian")
        file_header = "<" .. FILE_HEADER
        rec_header  = "<" .. REC_HEADER
    elseif magic == SWAPPED_MAGIC then
        dprint2("file is big-endian")
        file_header = ">" .. FILE_HEADER
        rec_header  = ">" .. REC_HEADER
    else
        dprint("magic was:",magic," so not a pcap file")
        return false
    end

    local nettype

    magic, VERSION_MAJOR, VERSION_MINOR, TIMEZONE, SIGFIGS, SNAPLEN, nettype = Struct.unpack(file_header, line)

    if not magic then
        dprint("parse_file_header: failed to unpack header struct")
        return false
    end

    dprint("parse_file_header: got magic=",magic, ", major version=",VERSION_MAJOR, ", minor=",VERSION_MINOR,
            ", timezone=",TIMEZONE, ", sigfigs=",SIGFIGS, "snaplen=",SNAPLEN, ", nettype =",nettype)

    -- wireshark only supports version 2.0 and later
    if VERSION_MAJOR < 2 then
        dprint("got version =",VERSION_MAJOR,"but only version 2 or greater supported")
        return false
    end

    -- convert pcap file interface type to wtap number type
    ENCAP_TYPE = pcap2wtap[nettype]
    if not ENCAP_TYPE then
        dprint("file nettype",nettype,"couldn't be mapped to wireshark wtap type")
        return false
    end


    if SNAPLEN > WTAP_MAX_PACKET_SIZE then
        SNAPLEN = WTAP_MAX_PACKET_SIZE
    end

    --ok, it's a pcap file
    dprint2("parse_file_header: success")
    return true
end

----------------------------------------
-- this is used by both read() and seek_read()
-- the calling function to this should have already set the file position correctly
read_common = function(funcname, file, frame)
    dprint2(funcname,": read_common() called")

    -- first parse the record header, which will set the FrameInfo fields
    if not parse_rec_header(funcname, file, frame) then
        dprint2(funcname, ": read_common: hit end of file or error")
        return false
    end

    frame.encap = ENCAP_TYPE

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
parse_rec_header = function(funcname, file, frame)
    dprint2(funcname,": parse_rec_header() called")

    local line = file:read(REC_HDR_LEN)

    -- it's ok for us to not be able to read it, if it's end of file
    if not line then return false end

    -- this is: time_sec, time_usec, capture_len, original_len
    local fields = { Struct.unpack(rec_header, line) }

    -- sanity check; also note that Struct.unpack() returns the fields plus
    -- a number of where in the line it stopped reading (ie, the end in this case)
    -- so we got back number of fields + 1
    if #fields ~= NUM_REC_FIELDS + 1 then
        dprint(funcname, ": parse_rec_header: failed to read the record header")
        return nil
    end

    -- we could just do this:
    --frame.time = fields[1] + (fields[2] / 1000000)
    -- but Lua numbers are doubles, which lose precision in the fractional part
    -- so we use a NSTime() object instead; remember though that an NSTime takes
    -- nanoseconds for its second arg, and pcap's are only microseconds, so *1000
    frame.time = NSTime(fields[1], fields[2]*1000)

    -- sanity check, verify captured length isn't more than original length
    if fields[3] > fields[4] then
        dprint("captured length of",fields[3],"is bigger than original length of",fields[4])
        -- swap them
        local caplen = fields[3]
        fields[3] = fields[4]
        fields[4] = caplen
    end

    if fields[3] > WTAP_MAX_PACKET_SIZE then
        dprint("Got a captured_length of",fields[3],"which is too big")
        return nil
    end

    frame.captured_length = fields[3]
    frame.original_length = fields[4]

    frame.flags = wtap_presence_flags.TS + wtap_presence_flags.CAP_LEN -- for timestamp|cap_len

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

-- we can't reuse the variables we used in the reader, because this script might be sued to both
-- open a file for reading and write it out, at the same time, so we prepend 'W_' for the writer's
-- versions. Normally I'd put this type of stuff in a class table and just create a new instance,
-- but I didn't want to confuse people with Lua class models in this script
local W_VERSION_MAJOR = 2
local W_VERSION_MINOR = 4
local W_TIMEZONE = 0
local W_SIGFIGS = 0
local W_SNAPLEN = 0
local W_ENCAP_TYPE = wtap.UNKNOWN
-- write out things in little-endian order
local w_file_header = "<" .. FILE_HEADER
local w_rec_header = "<" .. REC_HEADER
local TSPRECISION = wtap_filetypes.TSPREC_USEC

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

    -- write out file header
    local hdr = Struct.pack(w_file_header,
        MAGIC, W_VERSION_MAJOR, W_VERSION_MINOR,
        W_TIMEZONE, W_SIGFIGS, capture.snapshot_length, wtap2pcap(capture.encap))

    if not hdr then
        dprint("write_open: error generating file header")
        return false
    end

    dprint2("write_open generating:",Struct.tohex(hdr))

    if not file:write(hdr) then
        dprint("write_open: error writing file header to file")
        return false
    end

    return true
end

local function write(file, frame)
    dprint2("write() called")

    -- write out record header: time_sec, time_usec, capture_len, original_len

    -- first get times
    local nstime = frame.time

    -- pcap format is in usecs
    local nsecs = nstime.nsecs / 1000

    local hdr = Struct.pack(w_rec_header, nstime.secs, nsecs, frame.captured_length, frame.original_length)

    if not hdr then
        dprint("write_open: error generating record header")
        return false
    end

    if not file:write(hdr) then
        dprint("write_open: error writing record header to file")
        return false
    end

    -- we could write the packet data the same way, by getting frame.data and writing it out
    -- but we can avoid copying those bytes into Lua by using the write_data() function
    if not frame:write_data(file) then
        dprint("write_open: error writing record data to file")
        return false
    end

    return true
end

local function write_close(file)
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
