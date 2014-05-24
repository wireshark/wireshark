------------------------------------------
-- acme_file_reader.lua
-- Author: Hadriel Kaplan (hadrielk at yahoo dot com)
-- version = 1.0
-- date = 3/3/2014
------------------------------------------
--[[
    This is a Wireshark Lua-based capture file reader.
    This "capture file" reader reads message logs from Acme Packet (now Oracle) Session Border Controllers,
    such as sipmsg.log files.  There are several variants of the log file format, as well as some changes that
    can happen based on how the log file is generated and retrieved; for example if it's generated through a
    'tail' command, or FTP'ed by a FTP client which adds carriage-returns.  This Lua file reader tries to handle
    such conditions.

    Note: this script wasn't written to be super-efficient, nor clever.  When you've been writing Lua for a while
    you get used to writing in a different, more elegant fashion than this script is; but other people find it
    hard to read such Lua code, so I've tried to keep this simpler.

    Features:
    -handles sipmsg type logs, sipdns type logs, algd type logs
    -handles both IPv4 and IPv6, for both UDP and TCP
    -reads sipmsg logs from 3800, 4250, 4500, 9200, 6300 SBCs
    -handles logs with extra carriage-returns and linefeeds, such as from certain FTP'ed cases
    -handles logs generated/copied from a 'tail' command on the SBC ACLI
    -handles MBCD messages in logs, and puts their decoded ascii description in comments in Wireshark

    Issues:
    -for very large logs (many megabytes), it takes a long time (many minutes)
    -creates fake IP and UDP/TCP headers, which might be misleading
    -has to guess sometimes, though it hasn't guessed wrong yet as far as I know

    To-do:
    - make it use Struct.tohex/fromhex now that we have the Struct library in Wireshark
    - make it use a linux cooked-mode pseudo-header (see http://wiki.wireshark.org/SLL)
    - make it use preferences, once I write C-code for Wireshark to do that :)
    - rewrite some of the pattern searches to use real regex/PCRE instead? It's not in Wireshark yet,
        but it's coming (see https://code.wireshark.org/review/#/c/332/)

Example SIP over UDP message:
Aug 26 19:25:10.685 On [5:0]2.1.1.1:5060 received from 2.1.2.115:5060
REGISTER sip:2.1.1.1:5060 SIP/2.0
Via: SIP/2.0/UDP 2.1.2.115:5060;branch=z9hG4bK6501441021660x81000412
From: <sip:public_115@2.1.1.1:5060>;tag=520052-7015560x81000412
To: <sip:public_115@2.1.1.1:5060>
Call-ID: 680192-4234150x81000412@2.1.2.115
CSeq: 247 REGISTER
Contact: <sip:public_115@2.1.2.115:5060;transport=udp>
Expires: 300
Max-Forwards: 70
Authorization: Digest username="public_115",realm="empirix.com",uri="sip:2.1.1.1",response="5d61837cc54dc27018a40f2532e622de",nonce="430f6ff09ecd8c3fdfc5430b6e7e437a4cf77057",algorithm=md5
Content-Length: 0


----------------------------------------
Another one:
2007-03-06 13:38:48.037 OPENED
2007-03-06 13:38:48.037 OPENED
2007-03-06 13:38:48.037 OPENED
Mar  6 13:38:54.959 On [1:0]135.25.29.135:5060 received from 192.168.109.138:65471
OPTIONS sip:135.25.29.135 SIP/2.0
Accept: application/sdp
User-Agent: ABS GW v5.1.0
To: sip:135.25.29.135
From: sip:192.168.109.138;tag=a2a090ade36bb108da70b0c8f7ba02e9
Contact: sip:192.168.109.138
Call-ID: 8c0296da4a0d9f4d97e1389cd28d2352@172.16.6.114
CSeq: 347517161 OPTIONS
Via: SIP/2.0/UDP 192.168.109.138;branch=z9hG4bK21feac80fe9a63c1cf2988baa2af0849
Max-Forwards: 70
Content-Length: 0


----------------------------------------
Another SIP over UDP (from 9200):
File opened.
Jun  8 14:34:22.599 UDP[3:0]10.102.131.194:5060 OPENED
Jun  8 14:34:22.616 UDP[6:0]10.102.130.185:5060 OPENED
Jun  8 14:34:49.416 On [6:0]10.102.130.185:5060 received from 10.102.130.150:5060
REGISTER sip:csp.noklab.net SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK26b7a48d
From: sip:34903@csp.noklab.net
To: sip:34903@csp.noklab.net
Call-ID: 003094c3-a0160002-23aa7e86-29e5808d@192.168.1.100
CSeq: 144 REGISTER
User-Agent: CSCO/7
Contact: <sip:34903@192.168.1.100:5060>
Content-Length: 0
Expires: 3600


----------------------------------------

Example SIP over TCP message (note it ends in the middle of a header name):
Jan 12 00:03:54.700 On 172.25.96.200:8194 received from 172.25.32.28:5060
SIP/2.0 200 OK
From: Unavailable <sip:Unavailable@172.25.96.200:5060;user=phone>;tag=1200822480
To: 24001900011 <sip:0011@172.25.32.28:5060;user=phone>;tag=03c86c0b27df1b1254aeccbc000
Call-ID: 7f6b0887-1d313896-1511da31-b045@144.229.136.111
CSe
----------------------------------------

Example SIP Pre and Post-NAT messages:
Post-NAT from private<realm=e911core> encoded:
SIP/2.0 302 Moved Temporarily
Call-ID: SD27o9f04-fcc63aa885c83e22a1be64cfc210b55e-vjvtv00
CSeq: 2 INVITE
From: <sip:7866932005@127.1.0.100:5060;user=phone;e911core=TSD5051AEPCORE-dnamt76v6nm04;CKE=BSLD-5cuduig6t52l2;e911vpn=TSD5051AEPVPN-7gdq13vt8fi59>;tag=SD27o9f04-10000000-0-1424021314
To: <sip:911@127.0.0.100;user=phone;CKE=BSLD-8blt7m3dhnj17>;tag=10280004-0-1239441202
Via: SIP/2.0/UDP 127.254.254.1:5060;branch=z9hG4bK5i4ue300dgrdras7q281.1
Server: DC-SIP/1.2
Content-Length: 0
Contact: <sip:1111119999@127.0.0.100:5060;e911core=TSD5051AEPCORE-5n86t36uuma01>


----------------------------------------
Pre-NAT to private<realm=e911core> decode:
ACK sip:911@127.0.0.100;user=phone;CKE=BSLD-8blt7m3dhnj17 SIP/2.0
Via: SIP/2.0/UDP 127.254.254.1:5060;branch=z9hG4bK5i4ue300dgrdras7q281.1
Call-ID: SD27o9f04-fcc63aa885c83e22a1be64cfc210b55e-vjvtv00
CSeq: 2 ACK
From: <sip:7866932005@127.1.0.100:5060;user=phone;e911core=TSD5051AEPCORE-dnamt76v6nm04;CKE=BSLD-5cuduig6t52l2;e911vpn=TSD5051AEPVPN-7gdq13vt8fi59>;tag=SD27o9f04-10000000-0-1424021314
To: <sip:911@127.0.0.100;user=phone;CKE=BSLD-8blt7m3dhnj17>;tag=10280004-0-1239441202
Max-Forwards: 70


----------------------------------------

Example DNS message:
Nov  1 23:03:12.811 On 10.21.232.194:1122 received from 10.21.199.204:53
DNS Response 3916 flags=8503 q=1 ans=0 auth=1 add=0 net-ttl=0
  Q:NAPTR 7.6.5.4.3.2.1.0.1.2.e164
  NS:SOA e164 ttl=0 netnumber01
         rname=user.netnumber01
         ser=223 ref=0 retry=0 exp=0 minttl=0

  0000: 0f 4c 85 03 00 01 00 00 00 01 00 00 01 37 01 36   .L...........7.6
  0010: 01 35 01 34 01 33 01 32 01 31 01 30 01 31 01 32   .5.4.3.2.1.0.1.2
  0020: 04 65 31 36 34 00 00 23 00 01 04 65 31 36 34 00   .e164..#...e164.
  0030: 00 06 00 01 00 00 00 00 00 33 0b 6e 65 74 6e 75   .........3.netnu
  0040: 6d 62 65 72 30 31 00 04 75 73 65 72 0b 6e 65 74   mber01..user.net
  0050: 6e 75 6d 62 65 72 30 31 00 00 00 00 df 00 00 00   number01........
  0060: 00 00 00 00 00 00 00 00 00 00 00 00 00            .............

----------------------------------------
Example MGCP message (note the IP/UDP headers are in the hex):
Mar  1 14:37:26.683 On [0:803]172.16.84.141:2427 sent to 172.16.74.100:2427
Packet:
  0000: 00 04 00 00 00 01 00 02 00 00 03 23 0a ad 00 c9   ...........#....
  0010: 45 00 00 a8 23 36 00 00 3c 11 63 fd ac 10 54 8d   E...#6..<.c...T.
  0020: ac 10 4a 64 09 7b 09 7b 00 94 16 c2 32 35 30 20   ..Jd.{.{....250

250 55363 Connection Deleted
P: PS=6551, OS=1048160, PR=6517, OR=1042720, PL=0, JI=1, LA=5, PC/RPS=6466, PC/ROS=1034560, PC/RPL=0, PC/RJI=0

----------------------------------------
Example MBCD message:
Mar  1 14:37:26.672 On 127.0.0.1:2946 sent to 127.0.0.1:2944
  0000: ac 3e fd a8 01 01 77 36 9e 00 37 10 0c 34 4c bc   .>....w6..7..4L.
  0010: 00 30 23 0c 34 4c bc 00 11 33 00 0e 35 00 04 00   .0#.4L...3..5...
  0020: 00 00 00 30 00 04 00 00 00 00 23 0c 34 4c bd 00   ...0......#.4L..
  0030: 11 33 00 0e 35 00 04 00 00 00 00 30 00 04 00 00   .3..5......0....
  0040: 00 00                                             ..
Transaction = 24589982 {
  Context = 204754108 {
    Subtract = 204754108 {
      Audit {
        Stats,
        Flow
      }
    },
    Subtract = 204754109 {
      Audit {
        Stats,
        Flow
      }
    }
  }
}
----------------------------------------

]]----------------------------------------

-- debug printer, set DEBUG to true to enable printing debug info
-- set DEBUG2 to true to enable really verbose printing
local DEBUG, DEBUG2 = true, false

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

-- this should be done as a preference setting
local ALWAYS_UDP = true


local fh = FileHandler.new("Oracle Acme Packet logs", "acme",
                "A file reader for Oracle Acme Packet message logs such as sipmsg.log","rs")


-- There are certain things we have to create fake state/data for, because they
-- don't exist in the log file for example to create IP headers we have to create
-- fake identification field values, and to create timestamps we have to guess the
-- year (and in some cases month/day as well), and for TCP we have to create fake
-- connection info, such as sequence numbers.  We can't simply have a global static
-- variable holding such things, because Wireshark reads the file sequentially at
-- first, but then calls seek_read for random packets again and we don't want to
-- re-create the fake info again because it will be wrong.  So we need to create it
-- for each packet and remember what we created for each packet, so that seek_read
-- gets the same values. We could store the variables in a big table, keyed by the
-- specific header info line for each one; but instead we'll key it off of the file
-- position number, since read() sets it for Wireshark and seek_read() gets it from
-- Wireshark. So we'll have a set of global statics used during read(), but the
-- actual per-packet values will be stored in a table indexed/keyed by the file
-- position number.  A separate table holds TCP peer connection info as described
-- later.

-- I said above that this state is "global", but really it can't be global to this
-- whole script file, because more than one file can be opened for reading at the
-- same time. For example if the user presses the reload button, the capture file
-- will be opened for reading before the previous (same) one is closed. So we have
-- to store state per-file. The good news is Wireshark gives us a convenient way to
-- do that, using the CaptureInfo.private_table attribute/member. We can save a Lua
-- table with whatever contents we want, to this private_table member, and get it
-- later during the other read/seek_read/cose function calls.

-- So to store this per-file state, we're going to use Lua class objects. They're
-- just Lua tables that have functions and meta-functions and can be treated like
-- objects in terms of syntax/behavior.

local State = {}
local State_mt = { __index = State }

function State.new()
    local new_class = {  -- the new instance
        -- stuff we need to keep track of to cerate fake info
        ip_ident = 0,
        tyear    = 0,
        tmonth   = 0,
        tmin     = 0,
        tsec     = 0,
        tmilli   = 0,
        nstime   = NSTime(),
        -- the following table holds per-packet info
        -- the key index will be a number - the file position - but it won't be an array type table (too sparse).
        -- Each packet's entry is a table holding the "static" variables for that packet; this sub-table will be
        -- an array style instead of hashmap, to reduce size/performance
        -- This table needs to be cleared whenever the file is closed/opened.
        packets = {},

        -- the following local table holds TCP peer "connection" info, which is basically
        -- TCP control block (TCB) type information; this is needed to create and keep track
        -- of fake TCP sockets/headers for messages that went over TCP, for example for fake
        -- sequence number info.
        -- The key index for this is the local+remote ip:port strings concatenated.
        -- The value is a sub-table, array style, holding the most recent sequence numbers.
        -- This whole table needs to be cleared whenever the file is closed/opened.
        tcb = {},

    }
    setmetatable( new_class, State_mt ) -- all instances share the same metatable
    return new_class
end

-- the indices for the State.packets{} variable sub-tables
local IP_IDENT  = 1
local TTIME     = 2
local LOCAL_SEQ = 3
local REMOTE_SEQ = 4

-- the indices for the State.tcb{} sub-tables
local TLOCAL_SEQ = 1
local TREMOTE_SEQ = 2

-- helper functions
local char = string.char
local floor = math.floor

-- takes a Lua number and converts it into a 2-byte string binary (network order)

local function dec2bin16(num)
    return Struct.pack(">I2",num)
end

-- takes a Lua number and converts it into a 4-byte string binary (network order)
local function dec2bin32(num)
    return Struct.pack(">I4",num)
end


-- function to skip log info before/between/after messages
local delim = "^%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-%-$"
-- words that must be found to be skipped.  "File ..." is found in 9200 logs)
local skiplist = { " OPENED", " CLOSED", " STARTED", " STOPPED", "^File ", delim }
-- pre/post NAT entries
local pre_nat_header_pattern = "^Pre%-NAT to private<realm=([^>]+)> decode:\r?$"
local post_nat_header_pattern = "^Post%-NAT from private<realm=([^>]+)> encoded:\r?$"

local function skip_ahead(file, line, position)
    repeat
        local found = #line == 0  -- will be false unless the line is empty
        for i, word in ipairs(skiplist) do
            if line:find(word) then
                found = true
                break
            end
        end
        if found then
            position = file:seek()
            line = file:read()
            if not line then return nil end
        elseif line:find(pre_nat_header_pattern) or line:find(post_nat_header_pattern) then
            -- skip the whole message
            found = true
            repeat
                line = file:read()
            until line:find(delim)
        end
    until not found
    return line, position
end

-- following pattern grabs month, day, hour, min, sec, millisecs
local header_time_pattern = "^(%u%l%l)  ?(%d%d?) (%d%d?):(%d%d):(%d%d)%.(%d%d%d) On "
-- tail'ed file has no month/day
local header_tail_time_pattern = "^(%d%d):(%d%d)%.(%d%d%d) On "

-- grabs local and remote IPv4:ports (not phy/vlan), and words in between (i.e., "sent to" or "received from")
local header_address_pattern = "(%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?):(%d+) (%l+ %l+) (%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?):(%d+) ?\r?$"
-- grabs local and remote IPv6:ports (not phy/vlan), and words in between (i.e., "sent to" or "received from")
local header_v6address_pattern = "%[([:%x]+)%]:(%d+) (%l+ %l+) %[([:%x]+)%]:(%d+) ?\r?$"

-- grabs phy/vlan info
local header_phy_pattern = "%[(%d+):(%d+)%]"

local SENT = 1
local RECV = 2
local function get_direction(phrase)
    if #phrase == 7 and phrase:find("sent to") then
        return SENT
    elseif #phrase == 13 and phrase:find("received from") then
        return RECV
    end
    dprint("direction phrase not found")
    return nil
end

-- monthlist table for getting month number value from 3-char name (number is table index)
local monthlist = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

-- Compute the difference in seconds between local time and UTC
-- from http://lua-users.org/wiki/TimeZone
local function get_timezone()
  local now = os.time()
  return os.difftime(now, os.time(os.date("!*t", now)))
end
local timezone = get_timezone()

function State:get_timestamp(line, file_position, seeking)
    local i, line_pos, month, day, hour, min, sec, milli = line:find(header_time_pattern)
    if not month then
        return
    end

    if seeking then
        -- we've seen this packet before, just go get the saved timestamp
        sec = self.packets[file_position][TTIME]
        if not sec then
            dprint("failed to get saved timestamp for packet at position:", file_position)
            return
        end
        return sec, line_pos
    end

    -- find the month's number
    for index, name in ipairs(monthlist) do
        if month == name then
            month = index
            break
        end
    end
    if type(month) ~= "number" then return end

    day = tonumber(day)
    hour = tonumber(hour)
    min = tonumber(min)
    sec = tonumber(sec)
    milli = tonumber(milli)

    if not day or not hour or not min or not sec or not milli then
        dprint("timestamp could not be determined")
        return nil
    end

    -- we don't know what year the log file was created, so we have to guess
    -- if we guess the current system year, then a log of December loaded in January will appear wrong,
    -- as will a log file which lasts over new year
    -- so we're going to check the current system month, and if it's less than the log file's then we'll
    -- assume the log file started last year; if the system month is larger or equal, then we'll assume the log
    -- file is of this year.  We only do this checking once per file.
    if self.tyear == 0 then
        local curr_year, curr_month = tonumber(os.date("%Y")), tonumber(os.date("%m"))
        if curr_month < month then
            -- use last year
            if curr_year > 0 then
                curr_year = curr_year - 1
            end
        end
        self.tyear = curr_year
    end

    -- if this message's month is less than previous message's, then year wrapped
    if month < self.tmonth then
        self.tyear = self.tyear + 1
    end
    self.tmonth = month

    local timet = os.time({ ["year"] = self.tyear, ["month"] = month, ["day"] = day, ["hour"] = hour, ["min"] = min, ["sec"] = sec })
    if not timet then
        dprint("timestamp conversion failed")
    end

    timet = timet + timezone

    -- make an NSTime
    self.nstime = NSTime(timet, milli * 1000000)
    self.packets[file_position][TTIME] = self.nstime

    timet = timet + (milli/1000)
    dprint2("found time of ", os.date("%c",timet), " with value=",timet)

    return self.nstime, line_pos
end

-- get_tail_time() gets a fictitious timestamp starting from 19:00:00 on Dec 31, 1969, and incrementing based
-- on the minutes/secs/millisecs seen (i.e., if the minute wrapped then hour increases by 1, etc.).
-- this is needed for tail'ed log files, since they don't show month/day/hour
function State:get_tail_time(line, file_position, seeking)
    local i, line_pos, min, sec, milli = line:find(header_tail_time_pattern)
    if not min then return end

    if seeking then
        -- we've seen this packet before, just go get the saved timestamp
        sec = self.packets[file_position][TTIME]
        if not sec then
            dprint("failed to get saved timestamp for packet at position:", file_position)
            return
        end
        return sec, line_pos
    end

    min = tonumber(min)
    sec = tonumber(sec)
    milli = tonumber(milli)

    if not min or not sec or not milli then
        dprint("timestamp could not be determined")
        return nil
    end

    -- get difference in time
    local tmin, tsec, tmilli, nstime = self.tmin, self.tsec, self.tmilli, self.nstime
    local ttime = nstime.secs

    -- min, sec, milli are what the log says this tail'ed packet is
    -- tmin, tsec, tmilli are what we got from last packet
    -- nstime is the unix time of that, and ttime is the seconds of that unix time

    -- if minutes wrapped, or they're equal but seconds wrapped, then handle it as if in the next hour
    if (min < tmin) or (min == tmin and sec < tsec)  or (min == tmin and sec == tsec and milli < tmilli) then
        -- something wrapped, calculate difference as if in next hour
        ttime = ttime + (((min * 60) + sec + 3600) - ((tmin * 60) + tsec))
    else
        ttime = ttime + (((min * 60) + sec) - ((tmin * 60) + tsec))
    end
    self.tmin, self.tsec, self.tmilli = min, sec, milli
    self.nstime = NSTime(ttime, milli * 1000000)
    self.packets[file_position][TTIME] = self.nstime

    return self.nstime, line_pos
end

local hexbin = {
        ["0"]=0, ["1"]=1, ["2"]=2, ["3"]=3, ["4"]=4, ["5"]=5, ["6"]=6, ["7"]=7, ["8"]=8, ["9"]=9, ["a"]=10, ["b"]=11, ["c"]=12, ["d"]=13, ["e"]=14, ["f"]=15,
        ["00"]=0, ["01"]=1, ["02"]=2, ["03"]=3, ["04"]=4, ["05"]=5, ["06"]=6, ["07"]=7, ["08"]=8, ["09"]=9, ["0a"]=10, ["0b"]=11, ["0c"]=12, ["0d"]=13, ["0e"]=14, ["0f"]=15,
        ["10"]=16, ["11"]=17, ["12"]=18, ["13"]=19, ["14"]=20, ["15"]=21, ["16"]=22, ["17"]=23, ["18"]=24, ["19"]=25, ["1a"]=26, ["1b"]=27, ["1c"]=28, ["1d"]=29, ["1e"]=30, ["1f"]=31,
        ["20"]=32, ["21"]=33, ["22"]=34, ["23"]=35, ["24"]=36, ["25"]=37, ["26"]=38, ["27"]=39, ["28"]=40, ["29"]=41, ["2a"]=42, ["2b"]=43, ["2c"]=44, ["2d"]=45, ["2e"]=46, ["2f"]=47,
        ["30"]=48, ["31"]=49, ["32"]=50, ["33"]=51, ["34"]=52, ["35"]=53, ["36"]=54, ["37"]=55, ["38"]=56, ["39"]=57, ["3a"]=58, ["3b"]=59, ["3c"]=60, ["3d"]=61, ["3e"]=62, ["3f"]=63,
        ["40"]=64, ["41"]=65, ["42"]=66, ["43"]=67, ["44"]=68, ["45"]=69, ["46"]=70, ["47"]=71, ["48"]=72, ["49"]=73, ["4a"]=74, ["4b"]=75, ["4c"]=76, ["4d"]=77, ["4e"]=78, ["4f"]=79,
        ["50"]=80, ["51"]=81, ["52"]=82, ["53"]=83, ["54"]=84, ["55"]=85, ["56"]=86, ["57"]=87, ["58"]=88, ["59"]=89, ["5a"]=90, ["5b"]=91, ["5c"]=92, ["5d"]=93, ["5e"]=94, ["5f"]=95,
        ["60"]=96, ["61"]=97, ["62"]=98, ["63"]=99, ["64"]=100, ["65"]=101, ["66"]=102, ["67"]=103, ["68"]=104, ["69"]=105, ["6a"]=106, ["6b"]=107, ["6c"]=108, ["6d"]=109, ["6e"]=110, ["6f"]=111,
        ["70"]=112, ["71"]=113, ["72"]=114, ["73"]=115, ["74"]=116, ["75"]=117, ["76"]=118, ["77"]=119, ["78"]=120, ["79"]=121, ["7a"]=122, ["7b"]=123, ["7c"]=124, ["7d"]=125, ["7e"]=126, ["7f"]=127,
        ["80"]=128, ["81"]=129, ["82"]=130, ["83"]=131, ["84"]=132, ["85"]=133, ["86"]=134, ["87"]=135, ["88"]=136, ["89"]=137, ["8a"]=138, ["8b"]=139, ["8c"]=140, ["8d"]=141, ["8e"]=142, ["8f"]=143,
        ["90"]=144, ["91"]=145, ["92"]=146, ["93"]=147, ["94"]=148, ["95"]=149, ["96"]=150, ["97"]=151, ["98"]=152, ["99"]=153, ["9a"]=154, ["9b"]=155, ["9c"]=156, ["9d"]=157, ["9e"]=158, ["9f"]=159,
        ["a0"]=160, ["a1"]=161, ["a2"]=162, ["a3"]=163, ["a4"]=164, ["a5"]=165, ["a6"]=166, ["a7"]=167, ["a8"]=168, ["a9"]=169, ["aa"]=170, ["ab"]=171, ["ac"]=172, ["ad"]=173, ["ae"]=174, ["af"]=175,
        ["b0"]=176, ["b1"]=177, ["b2"]=178, ["b3"]=179, ["b4"]=180, ["b5"]=181, ["b6"]=182, ["b7"]=183, ["b8"]=184, ["b9"]=185, ["ba"]=186, ["bb"]=187, ["bc"]=188, ["bd"]=189, ["be"]=190, ["bf"]=191,
        ["c0"]=192, ["c1"]=193, ["c2"]=194, ["c3"]=195, ["c4"]=196, ["c5"]=197, ["c6"]=198, ["c7"]=199, ["c8"]=200, ["c9"]=201, ["ca"]=202, ["cb"]=203, ["cc"]=204, ["cd"]=205, ["ce"]=206, ["cf"]=207,
        ["d0"]=208, ["d1"]=209, ["d2"]=210, ["d3"]=211, ["d4"]=212, ["d5"]=213, ["d6"]=214, ["d7"]=215, ["d8"]=216, ["d9"]=217, ["da"]=218, ["db"]=219, ["dc"]=220, ["dd"]=221, ["de"]=222, ["df"]=223,
        ["e0"]=224, ["e1"]=225, ["e2"]=226, ["e3"]=227, ["e4"]=228, ["e5"]=229, ["e6"]=230, ["e7"]=231, ["e8"]=232, ["e9"]=233, ["ea"]=234, ["eb"]=235, ["ec"]=236, ["ed"]=237, ["ee"]=238, ["ef"]=239,
        ["f0"]=240, ["f1"]=241, ["f2"]=242, ["f3"]=243, ["f4"]=244, ["f5"]=245, ["f6"]=246, ["f7"]=247, ["f8"]=248, ["f9"]=249, ["fa"]=250, ["fb"]=251, ["fc"]=252, ["fd"]=253, ["fe"]=254, ["ff"]=255
}

local function iptobytes(ipaddr)
    local bytes = { ipaddr:match("(%d+)%.(%d+)%.(%d+)%.(%d+)") }
    if not #bytes == 4 then
        dprint("failed to get ip address bytes for '", ipaddr, "'")
        return
    end
    local ip = ""
    for i, byte in ipairs(bytes) do
        ip = ip .. char(tonumber(byte))
    end
    return ip
end

local function hexword2bin(word)
    if #word == 4 then
        return char(hexbin[word:sub(1,2)], hexbin[word:sub(3,4)])
    elseif #word == 3 then
        return char(hexbin[word:sub(1,1)], hexbin[word:sub(2,3)])
    elseif #word < 3 then
        return char(0, hexbin[word])
    end
    return nil  -- error
end

-- convert this 2620:0:60:8ac::102 to its 16-byte binary (=8 of 2-byte words)
local NUMWORDS = 8
local function ipv6tobytes(ipaddr)
    -- start with all 16 bytes being zeroes
    local words = { "\00\00", "\00\00", "\00\00", "\00\00", "\00\00", "\00\00", "\00\00", "\00\00" }
    -- now walk from front of ipv6 address string replacing byte numbers above;
    -- if we hit a "::", then jump to end and do it in reverse
    local colon_s, colon_e = ipaddr:find("::%x")
    if colon_s then
        -- there's a double-colon, so split the string and do the end first, backwards
        -- get each chunk first
        local t = {}
        local index, wordix = 1, NUMWORDS
        for w in string.gmatch(ipaddr:sub(colon_e - 1), ":(%x+)") do
            t[index] = hexword2bin(w)
            index = index + 1
        end
        for ix=index-1, 1, -1 do
            words[wordix] = t[ix]
            wordix = wordix - 1
        end
        ipaddr = ipaddr:sub(1, colon_s)
    end

    local i = 1
    for w in string.gmatch(ipaddr, "(%x+):?") do
        words[i] = hexword2bin(w)
        i = i + 1
    end

    if not #words == NUMWORDS then
        dprint("failed to get IPv6 address bytes for '", ipaddr, "'")
        return
    end

    return table.concat(words)
end

-- calculates checksum as done for IP, TCP, UDP
local function checksum(chunk)
    local sum = 0
    -- take every 2-byte value and add them up
    for one, two in chunk:gmatch("(.)(.)") do
        sum = sum + (string.byte(one) * 256) + (string.byte(two))
        while floor(sum / 65536) > 0 do
            -- add carry/overflow value
            sum = (sum % 65536) + (floor(sum / 65536))
        end
    end

    -- now get one's complement of that
    sum = 65535 - sum

    -- and return it as a 2-byte string
    return dec2bin16(sum)
end

----------------------------------------
-- protocol type number
local PROTO_UDP = "\17"
local PROTO_TCP = "\06"
-- enum
local IPv4 = 1
local IPv6 = 2
-- both type enums and header lengths
local UDP = 8
local TCP = 20

----------------------------------------
-- Packet creation/serialization occurs using a Lua class object model
-- There's a single base class 'Packet' which has data/methods every packet type has
-- 'RawPacket' and 'DataPacket' both derive from 'Packet'.
-- 'RawPacket' is for packets which the log file has the raw IP/UDP headers for,
--   such as ALG log messages (MGCP/NCS).  Since the IP headers are in them, we use those.
-- 'DataPacket' is for packets which the log file only has payload data for, and
--   we need to create fake IP/UDP or IP/TCP headers for.
-- 'BinPacket' and'AsciiPacket' both derive from 'DataPacket'.
-- 'BinPacket' is for binary-style logged packets, such as MBCD or DNS, while
-- 'AsciiPacket' is for ascii-style ones such as SIP.
-- 'DnsPacket' derives from 'BinPacket', for DNS-style logs.

-- Each class has a read_data() method, which reads in the packet data, builds the packet,
-- and sets the Wireshark buffer.  Some classes have a get_data() method which read_data()
-- calls, to get the payload data before building a fake packet.

-- The base Packet class has a get_hex_data() and get_ascii_data() methods, to get the payload
-- in either form, and those base methods are called by get_data() or read_data() of derived
-- classes.

-- For performance reasons, packet data is read line-by-line into a table (called bufftbl),
-- which is concatenated at the end.  This avoids Lua building interim strings and garbage
-- collecting them.  But it makes the code uglier.  The get_data()/get_hex_data()/get_ascii_data()
-- methods read into this table they get passed, while the read_data() functions handle managing
-- the table.

----------------------------------------
----------------------------------------
-- The base Packet class, from which others derive
-- all Packets have a ptype, timestamp, source and dest address:port, and data
--
local Packet = {}
local Packet_mt = { __index = Packet }

function Packet.new(state, timestamp, direction, source_ip, source_port, dest_ip, dest_port, ptype, ttype, file_position)
    local new_class = {  -- the new instance
        ["state"] = state,
        ["timestamp"] = timestamp,
        ["direction"] = direction,
        ["source_ip"] = source_ip,
        ["source_port"] = source_port,
        ["dest_ip"] = dest_ip,
        ["dest_port"] = dest_port,
        ["ptype"] = ptype,
        ["ttype"] = ttype,
        ["file_position"] = file_position
    }
    setmetatable( new_class, Packet_mt ) -- all instances share the same metatable
    return new_class
end

function Packet:set_comment(comment)
    self["comment"] = comment
end

function Packet:set_wslua_fields(frame)
    frame.time = self.timestamp
    frame.rec_type = wtap_rec_types.PACKET
    frame.flags = wtap_presence_flags.TS  -- for timestamp
    if self.comment then
        frame.comment = self.comment
        frame.flags = frame.flags + wtap_presence_flags.COMMENTS  -- comment flag
    end
    return true
end

local packet_hexline_pattern = "^  %x%x%x0: %x%x"
function Packet:get_hex_data(file, line, bufftbl, index)
    local start = index

    dprint2("Packet:get_hex_data() called")
    repeat
        for word in line:gmatch("(%x%x) ") do
            bufftbl[index] = char(hexbin[word])
            index = index + 1
            if ((index - start) % 16) == 0 then break end
        end
        line = file:read()
    until not line or not line:find(packet_hexline_pattern)

    return index - start, line
end

function Packet:get_ascii_data(file, line, bufftbl, index, only_newline)
    local bufflen = 0  -- keep tally of total length of payload
    local found_delim = true

    dprint2("Packet:get_ascii_data() called")
    repeat
        bufftbl[index] = line
        bufflen = bufflen + #line

        -- sanity check if line has "\r" at end, and if so only add \n
        if line:find("\r",-1,true) then
            bufftbl[index+1] = "\n"
            bufflen = bufflen + 1
            dprint2("Found carriage-return at end of line")
        elseif only_newline then
            -- only add a newline
            bufftbl[index+1] = "\n"
            bufflen = bufflen + 1
        else
            bufftbl[index+1] = "\r\n"
            bufflen = bufflen + 2
        end
        index = index + 2

        -- read next line now
        line = file:read()
        if not line then
            -- hit eof?
            found_delim = false
            break
        end

    until line:find(delim)

    -- get rid of last \r\n, if we found a dashed delimiter, as it's not part of packet
    if found_delim then
        bufflen = bufflen - bufftbl[index-1]:len()
        bufftbl[index-1] = nil
    end

    dprint2("Packet:get_ascii_data() returning", bufflen)
    return bufflen
end

----------------------------------------
-- RawPacket class, for packets that the log file contains the whole IP header for, such as algd logs
--
local RawPacket = {}
local RawPacket_mt = { __index = RawPacket }
setmetatable( RawPacket, Packet_mt ) -- make RawPacket inherit from Packet

function RawPacket.new(...)
    local new_class = Packet.new(...) -- the new instance
    setmetatable( new_class, RawPacket_mt ) -- all instances share the same metatable
    return new_class
end

function RawPacket:read_data(file, frame, line, seeking)
    local bufftbl = {}  -- table to hold data bytes
    local index = 1     -- start at first slot in array

    -- need to skip "Packet:" line and first 0000: line, it's internal junk
    line = file:read()
    line = file:read()

    dprint2("RawPacket:read_data() getting hex from line='", line, "'")
    local bufflen, line = self:get_hex_data(file, line, bufftbl, index)
    if not bufflen or bufflen < 21 then
        dprint("error getting binary data")
        return false
    end

    -- add remainder as more packet data, but first delete overlap
    -- see if frag bits are set in IP header, to see if UDP/TCP header exists
    if self.ptype == IPv4 then
        -- grab byte with frag flags and first byte of offset
        local flag = string.byte(bufftbl[7]) -- converts binary character to number
        local frag_offset = flag % 32 -- masks off upper 3 bits
        frag_offset = (frag_offset * 256) + string.byte(bufftbl[8])
        flag = floor(flag / 224)  -- shift right
        flag = flag % 2  -- mask upper bits
        if flag == 1 or frag_offset > 0 then
            -- we have a fragmented IPv4 packet, so no proto header
            -- only save first 20 bytes (the IP header)
            for i=bufflen, 21, -1 do
                bufftbl[i] = nil
            end
            bufflen = 20
        else
            -- only save first 20 + proto size bytes
            local save
            if bufftbl[10] == PROTO_UDP then
                save = 28
            elseif bufftbl[10] == PROTO_TCP then
                save = 40
            else
                dprint("failed to fix raw packet overlap")
                return
            end
            for i=bufflen, save+1, -1 do
                bufftbl[i] = nil
            end
            bufflen = save
        end
    end
    -- TODO: IPv6

    -- now read in rest of message, if any
    -- first skip extra empty newline
    if #line == 0 then
        line = file:read()
    end

    bufflen = bufflen + self:get_ascii_data(file, line, bufftbl, bufflen+1, true)

    frame.data = table.concat(bufftbl)

    return true
end

----------------------------------------
-- DataPacket class, for packets that the log file contains just the payload data for
--
local DataPacket = {}
local DataPacket_mt = { __index = DataPacket }
setmetatable( DataPacket, Packet_mt ) -- make DataPacket inherit from Packet

function DataPacket.new(...)
    local new_class = Packet.new(...) -- the new instance
    setmetatable( new_class, DataPacket_mt ) -- all instances share the same metatable
    return new_class
end

function DataPacket:set_tcbkey(key)
    self["tcbkey"] = key
    return
end

function DataPacket:build_ipv4_hdr(bufflen, proto, seeking)
    local len = bufflen + 20  -- 20 byte IPv4 header size

    -- figure out the ip identification value
    local ip_ident
    if seeking then
        ip_ident = self.state.packets[self.file_position][IP_IDENT]
    else
        -- increment ident value
        self.state.ip_ident = self.state.ip_ident + 1
        if self.state.ip_ident == 65536 then
            self.state.ip_ident = 1
        end
        ip_ident = self.state.ip_ident
        -- save it for future seeking
        self.state.packets[self.file_position][IP_IDENT] = ip_ident
    end

    -- use a table to concatenate as it's slightly faster that way
    local hdrtbl = {
        "\69\00",                   -- 1=ipv4 and 20 byte header length
        dec2bin16(len),             -- 2=packet length bytes
        dec2bin16(ip_ident),        -- 3=ident field bytes
        "\00\00\64",                -- 4=flags/fragment offset, ttl
        proto,                      -- 5=proto
        "\00\00",                   -- 6=checksum (using zero for now)
        iptobytes(self.source_ip),  -- 7=source ip
        iptobytes(self.dest_ip)     -- 8=dest ip
    }

    -- calc IPv4 header checksum, and set its value
    hdrtbl[6] = checksum(table.concat(hdrtbl))

    return table.concat(hdrtbl)
end

function DataPacket:build_ipv6_hdr(bufflen, proto)
    -- use a table to concatenate as it's slightly faster that way
    local hdrtbl = {
        "\96\00\00\00",                             -- 1=ipv6 version, class, label
        dec2bin16(bufflen),                         -- 2=packet length bytes
        proto .. "\64",                             -- 4=proto, ttl
        ipv6tobytes(self.source_ip),                -- 5=source ip
        ipv6tobytes(self.dest_ip)                   -- 6=dest ip
    }
    return table.concat(hdrtbl)
end

-- calculates TCP/UDP header checksums with pseudo-header info
function DataPacket:calc_header_checksum(bufftbl, bufflen, hdrtbl, proto)
    -- first create pseudo IP header
    if self.ptype == IPv4 then
        local iphdrtbl = {
            iptobytes(self.source_ip),  -- 1=source ip
            iptobytes(self.dest_ip),    -- 2=dest ip
            "\00",                      -- zeros
            proto,                      -- proto
            dec2bin16(bufflen)          -- payload length bytes
        }
        bufftbl[1] = table.concat(iphdrtbl)
    elseif self.ptype == IPv6 then
        local iphdrtbl = {
            ipv6tobytes(self.source_ip),    -- 1=source ip
            ipv6tobytes(self.dest_ip),      -- 2=dest ip
            "\00\00",                       -- zeroes
            dec2bin16(bufflen),             -- payload length bytes
            "\00\00\00",                    -- zeros
            proto                           -- proto
        }
        bufftbl[1] = table.concat(iphdrtbl)
    end

    -- and pseudo TCP or UDP header
    bufftbl[2] = table.concat(hdrtbl)

    -- see if payload is odd length
    local odd = false
    if bufflen % 2 == 1 then
        -- odd number of payload bytes, add zero byte at end
        odd = true  -- remember to undo this
        bufftbl[#bufftbl+1] = "\00"
    end

    local result = checksum(table.concat(bufftbl))

    -- remove pseudo-headers
    bufftbl[1] = nil
    bufftbl[2] = nil
    if odd then
        bufftbl[#bufftbl] = nil
    end

    return result
end


function DataPacket:build_udp_hdr(bufflen, bufftbl)
    local len = bufflen + 8  -- 8 for size of UDP header
    local hdrtbl = {
        dec2bin16(self.source_port), -- 1=source port bytes
        dec2bin16(self.dest_port),  -- 2=dest port bytes
        dec2bin16(len),             -- 3=payload length bytes
        "\00\00"   -- 4=checksum
    }
    if bufftbl then
        -- calc udp checksum (only done for IPv6)
        hdrtbl[4] = self:calc_header_checksum(bufftbl, len, hdrtbl, PROTO_UDP)
    end
    return table.concat(hdrtbl)
end


function DataPacket:build_tcp_hdr(bufflen, bufftbl, seeking)
    local len = bufflen + 20  -- 20 for size of TCP header

    local local_seq, remote_seq
    if seeking then
        local_seq = self.state.packets[self.file_position][LOCAL_SEQ]
        remote_seq = self.state.packets[self.file_position][REMOTE_SEQ]
    else
        -- find socket/tcb info for this "stream", create if not found
        if not self.state.tcb[self.tcbkey] then
            -- create them
            self.state.tcb[self.tcbkey] = {}
            local_seq = 1
            remote_seq = 1
            self.state.packets[self.file_position][LOCAL_SEQ] = 1
            self.state.packets[self.file_position][REMOTE_SEQ] = 1
            -- set tcb to next sequence numbers, so that the correct "side"
            -- acknowledges receiving these bytes
            if self.direction == SENT then
                -- this packet is being sent, so local sequence increases next time
                self.state.tcb[self.tcbkey][TLOCAL_SEQ] = bufflen+1
                self.state.tcb[self.tcbkey][TREMOTE_SEQ] = 1
            else
                -- this packet is being received, so remote sequence increases next time
                -- and local side will acknowldge it next time
                self.state.tcb[self.tcbkey][TLOCAL_SEQ] = 1
                self.state.tcb[self.tcbkey][TREMOTE_SEQ] = bufflen+1
            end
        else
            -- stream already exists, so send the current tcb seqs and update for next time
            if self.direction == SENT then
                -- this packet is being sent, so local sequence increases next time
                local_seq = self.state.tcb[self.tcbkey][TLOCAL_SEQ]
                remote_seq = self.state.tcb[self.tcbkey][TREMOTE_SEQ]
                self.state.tcb[self.tcbkey][TLOCAL_SEQ] = local_seq + bufflen
            else
                -- this packet is being received, so the "local" seq number of the packet is the remote's seq really
                local_seq = self.state.tcb[self.tcbkey][TREMOTE_SEQ]
                remote_seq = self.state.tcb[self.tcbkey][TLOCAL_SEQ]
                -- and remote seq needs to increase next time (remember local_seq is TREMOTE_SEQ)
                self.state.tcb[self.tcbkey][TREMOTE_SEQ] = local_seq + bufflen
            end
            self.state.packets[self.file_position][LOCAL_SEQ] = local_seq
            self.state.packets[self.file_position][REMOTE_SEQ] = remote_seq
        end
    end

    local hdrtbl = {
        dec2bin16(self.source_port),    -- 1=source port bytes
        dec2bin16(self.dest_port),      -- 2=dest port bytes
        dec2bin32(local_seq),           -- 3=sequence
        dec2bin32(remote_seq),          -- 4=ack number
        "\80\16\255\255",               -- 5=offset, flags, window size
        "\00\00",                       -- 6=checksum
        "\00\00"                        -- 7=urgent pointer
    }

    -- calc tcp checksum
    hdrtbl[6] = self:calc_header_checksum(bufftbl, len, hdrtbl, PROTO_TCP)

    return table.concat(hdrtbl)
end

function DataPacket:build_packet(bufftbl, bufflen, seeking)
    dprint2("DataPacket:build_packet() called with ptype=",self.ptype)
    if self.ptype == IPv4 then
        if self.ttype == UDP then
            bufftbl[2] = self:build_udp_hdr(bufflen)
            bufftbl[1] = self:build_ipv4_hdr(bufflen + 8, PROTO_UDP, seeking)
        elseif self.ttype == TCP then
            bufftbl[2] = self:build_tcp_hdr(bufflen, bufftbl, seeking)
            bufftbl[1] = self:build_ipv4_hdr(bufflen + 20, PROTO_TCP, seeking)
        end
    elseif self.ptype == IPv6 then
        -- UDP for IPv6 requires checksum calculation, so we can't avoid more work
        if self.ttype == UDP then
            bufftbl[2] = self:build_udp_hdr(bufflen, bufftbl)
            bufftbl[1] = self:build_ipv6_hdr(bufflen + 8, PROTO_UDP)
        elseif self.ttype == TCP then
            bufftbl[2] = self:build_tcp_hdr(bufflen, bufftbl, seeking)
            bufftbl[1] = self:build_ipv6_hdr(bufflen + 20, PROTO_TCP)
        end
    else
        dprint("DataPacket:build_packet: invalid packet type (neither IPv4 nor IPv6)")
        return nil
    end

    return table.concat(bufftbl)
end

-- for performance, we read each line into a table and concatenate it at end
-- but it makes this code super ugly
function DataPacket:read_data(file, frame, line, seeking)
    local bufftbl = { "", "" }  -- 2 slots for ip and udp/tcp headers
    local index = 3             -- start at third slot in array
    local comment               -- for any packet comments

    dprint2("DataPacket: read_data(): calling get_data")
    local bufflen = self:get_data(file, line, bufftbl, index)
    if not bufflen then
        dprint("DataPacket: error getting ascii or binary data")
        return false
    end

    local buff = self:build_packet(bufftbl, bufflen, seeking)

    frame.data = buff

    return true
end


----------------------------------------
-- BinPacket class, for packets that the log file contains binary payload data for, such as MBCD
--
local BinPacket = {}
local BinPacket_mt = { __index = BinPacket }
setmetatable( BinPacket, DataPacket_mt ) -- make BinPacket inherit from DataPacket

function BinPacket.new(...)
    local new_class = DataPacket.new(...) -- the new instance
    setmetatable( new_class, BinPacket_mt ) -- all instances share the same metatable
    return new_class
end

function BinPacket:get_comment_data(file, line, stop_pattern)
    local comments = {}

    while line and not line:find(stop_pattern) do
        if #line > 0 then
            comments[#comments+1] = line
            comments[#comments+1] = "\r\n"
        end
        line = file:read()
    end

    if #comments > 0 then
        -- get rid of extra "\r\n"
        comments[#comments] = nil
        self:set_comment(table.concat(comments))
    end

    return line
end

function BinPacket:get_data(file, line, bufftbl, index)
    local is_alg = false

    local bufflen, line = self:get_hex_data(file, line, bufftbl, index)

    -- now eat rest of message until delimiter or end of file
    -- we'll put them in comments
    line = self:get_comment_data(file, line, delim)

    -- return the bufflen, which is the same as number of table entries we made
    return bufflen
end

----------------------------------------
-- DnsPacket class, for DNS packets (which are binary but with comments at top)
--
local DnsPacket = {}
local DnsPacket_mt = { __index = DnsPacket }
setmetatable( DnsPacket, BinPacket_mt ) -- make DnsPacket inherit from BinPacket

function DnsPacket.new(...)
    local new_class = BinPacket.new(...) -- the new instance
    setmetatable( new_class, DnsPacket_mt ) -- all instances share the same metatable
    return new_class
end

local binpacket_start_pattern = "^  0000: %x%x %x%x %x%x %x%x %x%x %x%x %x%x %x%x "
function DnsPacket:get_data(file, line, bufftbl, index)
     -- it's UDP regardless of what parse_header() thinks
    self.ttype = UDP

    -- comments are at top instead of bottom of message
    line = self:get_comment_data(file, line, binpacket_start_pattern)

    local bufflen, line = self:get_hex_data(file, line, bufftbl, index)

    -- now eat rest of message until delimiter or end of file
    while line and not line:find(delim) do
        line = file:read()
    end

    -- return the bufflen, which is the same as number of table entries we made
    return bufflen
end

----------------------------------------
-- AsciiPacket class, for packets that the log file contains ascii payload data for
--
local AsciiPacket = {}
local AsciiPacket_mt = { __index = AsciiPacket }
setmetatable( AsciiPacket, DataPacket_mt ) -- make AsciiPacket inherit from DataPacket

function AsciiPacket.new(...)
    local new_class = DataPacket.new(...) -- the new instance
    setmetatable( new_class, AsciiPacket_mt ) -- all instances share the same metatable
    return new_class
end

function AsciiPacket:get_data(file, line, bufftbl, index)
    return self:get_ascii_data(file, line, bufftbl, index)
end


----------------------------------------
-- To determine packet type, we peek at the first line of 'data' following the log
-- message header.  Its pattern determines the Packet object type.
-- The following are the patterns we look for; if it doesn't match one of these,
-- then it's an AsciiPacket:
local packet_patterns = {
    { "^  0000: %x%x %x%x %x%x %x%x %x%x %x%x %x%x %x%x ", BinPacket },
    { "^Packet:$", RawPacket },
    { "^DNS Query %d+ flags=%d+ q=%d+ ans=%d+", DnsPacket },
    { "^DNS Response %d+ flags=%d+ q=%d+ ans=%d+", DnsPacket }
}
-- indeces for above
local PP_PATTERN = 1
local PP_CLASS = 2

local function get_packet_class(line)
    for i, t in ipairs(packet_patterns) do
        if line:find(t[PP_PATTERN]) then
            dprint2("got class type=",i)
            return t[PP_CLASS]
        end
    end
    dprint2("got class type AsciiPacket")
    return AsciiPacket
end

----------------------------------------
-- parses header line
-- returns nil on failure
-- the header lines look like this:
-- Aug 10 14:30:11.134 On [1:544]10.201.145.237:5060 received from 10.210.1.193:5060
-- this one has no phy/vlan info in brackets:
-- Mar  6 13:39:06.122 On 127.0.0.1:2945 sent to 127.0.0.1:2944
-- this one is IPv6:
-- Aug 10 14:30:11.140 On [3:0][2620:0:60:8ac::102]:5060 sent to [2620:0:60:8ab::12]:5060
-- this is from a tail'ed log output:
-- 52:22.434 On [0:0]205.152.56.211:5060 received from 205.152.56.75:5060
local loopback_pattern = "^127%.0%.0%.%d+$"
local function parse_header(state, file, line, file_position, seeking)

    if seeking then
        -- verify we've seen this packet before
        if not state.packets[file_position] then
            dprint("parse_header: packet at file position ", file_position, " not saved previously")
            return
        end
    else
        -- first time through, create sub-table for the packet
        state.packets[file_position] = {}
    end

    -- get time info, and line match ending position
    local timestamp, line_pos = state:get_timestamp(line, file_position, seeking)
    if not timestamp then
        -- see if it's a tail'ed log instead
        timestamp, line_pos = state:get_tail_time(line, file_position, seeking)
    end

    if not timestamp then
        dprint("parse_header: could not parse time portion")
        return
    end

    local ptype, ttype = IPv4, UDP

    -- get phy/vlan if present
    -- first skip past time portion
    local phy, vlan, i, j, k
    line_pos = line_pos + 1
    i, j, phy, vlan = line:find(header_phy_pattern, line_pos)
    if i then
        phy = tonumber(phy)
        vlan = tonumber(vlan)
        line_pos = j  -- skip past this portion for next match
    else
        -- if there's no phy/vlan info, then assume it's TCP (unless it's loopback address we'll check later)
        ttype = TCP
    end

    -- get addresses and direction
    local local_ip, local_port, direction, remote_ip, remote_port = line:match(header_address_pattern, line_pos)
    if not local_ip then
        -- try IPv6
        local_ip, local_port, direction, remote_ip, remote_port = line:match(header_v6address_pattern, line_pos)
        if not local_ip then
            dprint("parse_header: could not parse address portion")
            return nil
        end
        ptype = IPv6
    end

    if local_ip:find(loopback_pattern) and remote_ip:find(loopback_pattern) then
        -- internal loopback packets never have phy/vlan but are always UDP messages (for all intents)
        ttype = UDP
    end

    -- override above decisions based on configuration
    if ALWAYS_UDP then
        ttype = UDP
    end

    direction = get_direction(direction)
    if direction == nil then
        dprint("parse_header: failed to convert direction")
        return nil
    end

    local source_ip, source_port, dest_ip, dest_port = local_ip, local_port, remote_ip, remote_port
    if direction == RECV then
        -- swap them
        source_ip, source_port, dest_ip, dest_port = remote_ip, remote_port, local_ip, local_port
    end
    -- convert
    source_port = tonumber(source_port)
    dest_port = tonumber(dest_port)

    -- peek at next line to determine packet type
    local position = file:seek()
    line = file:read()
    dprint2("parse_header: peeking at line='", line, "'")
    packet_class = get_packet_class(line)
    file:seek("set", position)  -- go back

    dprint2("parse_header calling packet_class.new with:",
            tostring(timestamp), direction, source_ip, source_port,
            dest_ip, dest_port, ptype, ttype, file_position)

    local packet = packet_class.new(state, timestamp, direction, source_ip, source_port, dest_ip, dest_port, ptype, ttype, file_position)
    if not packet then
        dprint("parse_header: parser failed to create Packet object")
    end

    if ttype == TCP then
        -- if the packet is tcp type, then set the key for TCB table lookup
        packet:set_tcbkey(table.concat({ "[", local_ip, "]:", local_port, "->[", remote_ip, "]:", remote_port }))
    end

    return packet
end


----------------------------------------
-- file handling functions for Wireshark to use

-- The read_open is called by Wireshark once per file, to see if the file is this reader's type.
-- It passes in (1) a File and (2) CaptureInfo object to this function
-- Since there is no exact magic sequence to search for, we have to use heuristics to guess if the file
-- is our type or not, which we do by parsing a message header.
-- Since Wireshark uses the file cursor position for future reading of this file, we also have to seek back to the beginning
-- so that our normal read() function works correctly.
local function read_open(file, capture)
    dprint2("read_open called")
    -- save current position to return later
    local position = file:seek()

    local line = file:read()
    if not line then return false end

    dprint2("read_open: got this line begin:\n'", line, "'")

    line, position = skip_ahead(file, line, position)
    if not line then return false end

    dprint2("read_open: got this line after skip:\n'", line, "', with position=", position)

    local state = State.new()

    if parse_header(state, file, line, position) then
        dprint2("read_open success")

        file:seek("set",position)

        capture.time_precision = wtap_filetypes.TSPREC_MSEC  -- for millisecond precision
        capture.encap = wtap.RAW_IP -- whole file is raw IP format
        capture.snapshot_length = 0 -- unknown snaplen
        capture.comment = "Oracle Acme Packet SBC message log"
        capture.os = "VxWorks or Linux"
        capture.hardware = "Oracle Acme Packet SBC"

        -- reset state variables
        capture.private_table = State.new()

        dprint2("read_open returning true")
        return true
    end

    dprint2("read_open returning false")
    return false
end

----------------------------------------
-- this is used by both read() and seek_read()
local function read_common(funcname, file, capture, frame, position, seeking)
    dprint2(funcname, "read_common called")
    local state = capture.private_table

    if not state then
        dprint(funcname, "error getting capture state")
        return false
    end

    local line = file:read()
    if not line then
        dprint(funcname, "hit end of file")
        return false
    end
    line, position = skip_ahead(file, line, position)
    if not line then
        if file:read(0) ~= nil then
            dprint(funcname, "did not hit end of file after skipping but ending anyway")
        else
            dprint2(funcname, "hit end of file after skipping")
        end
        return false
    end

    dprint2(funcname, ": parsing line='", line, "'")
    local phdr = parse_header(state, file, line, position, seeking)
    if not phdr then
        dprint(funcname, "failed to parse header")
        return false
    end

    line = file:read()

    dprint2(funcname,": calling class object's read_data()")
    phdr:read_data(file, frame, line, seeking)

    if not phdr:set_wslua_fields(frame) then
        dprint(funcname, "failed to set Wireshark packet header info")
        return
    end

    dprint2(funcname, "read_common returning position")
    return position
end

----------------------------------------
-- Wireshark/tshark calls read() for each frame/record in the file
-- It passes in (1) a File, (2) CaptureInfo, and (3) a FrameInfo object to this function
-- It expects in return the file offset position the record starts at,
-- or nil/false if there's an error or end-of-file is reached.
-- The offset position is used later: wireshark remembers it and gives
-- it to seek_read() at various random times
local function read(file, capture, frame)
    dprint2("read called")
    local position = file:seek()
    position = read_common("read", file, capture, frame, position)
    if not position then
        if file:read(0) ~= nil then
            dprint("read failed to call read_common")
        else
            dprint2("read: reached end of file")
        end
        return false
    end
    return position
end

----------------------------------------
-- Wireshark/tshark calls seek_read() for each frame/record in the file, at random times
-- It passes in (1) File, (2) CaptureInfo, (3) FrameInfo, and (4) the offset position number
-- It expects in return true for successful parsing, or nil/false if there's an error.
local function seek_read(file, capture, frame, offset)
    dprint2("seek_read called")
    file:seek("set",offset)
    if not read_common("seek_read", file, capture, frame, offset, true) then
        dprint("seek_read failed to call read_common")
        return false
    end
    return true
end

----------------------------------------
-- Wireshark/tshark calls read_close() when it's closing the file completely
-- It passes in (1) a File and (2) CaptureInfo object to this function
-- this is a good opportunity to clean up any state you may have created during
-- file reading.
-- In our case there *is* state to reset, but we only saved it in
-- the capture.private_table, so Wireshark will clean it up for us.
local function read_close(file, capture)
    dprint2("read_close called")
    return true
end

----------------------------------------
-- An often unused function, Wireshark calls this when the sequential walk-through is over
-- It passes in (1) a File and (2) CaptureInfo object to this function
-- (i.e., no more calls to read(), only to seek_read()).
-- In our case there *is* some state to reset, but we only saved it in
-- the capture.private_table, so Wireshark will clean it up for us.
local function seq_read_close(file, capture)
    dprint2("seq_read_close called")
    return true
end

-- set above functions to the FileHandler
fh.read_open = read_open
fh.read = read
fh.seek_read = seek_read
fh.read_close = read_close
fh.seq_read_close = seq_read_close
fh.extensions = "log" -- this is just a hint

-- and finally, register the FileHandler!
register_filehandler(fh)
