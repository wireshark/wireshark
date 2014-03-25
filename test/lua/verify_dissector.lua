-- This is a test script for tshark.
-- This script runs inside tshark.
-- FIRST run tshark with the "dns_dissector.lua" plugin, with the dns_port.pcap file,
-- and with full tree output (-V switch).  Pipe that to a file named testin.txt.
-- This verify script then reads in that testin.txt.
--
-- tshark -r bogus.cap -X lua_script:<path_to_testdir>/lua/verify_dns_dissector.lua

local function testing(...)
    print("---- Testing "..tostring(...).." ----")
end

local lines = {
    {
        "MyDNS Protocol",
        "Transaction ID: 42",
        "Flags: 0x0100",
        "0... .... .... .... = Response: this is a query",
        "[Expert Info (Chat/Request): DNS query message]",
        "[DNS query message]",
        "[Severity level: Chat]",
        "[Group: Request]",
       ".000 0... .... .... = Opcode: 0",
        ".... ..0. .... .... = Truncated: False",
        ".... ...1 .... .... = Recursion desired: yes",
        ".... .... .0.. .... = World War Z - Reserved for future use: 0x0000",
        ".... .... ...0 .... = Checking disabled: False",
        "Number of Questions: 1",
        "Number of Answer RRs: 0",
        "Number of Authority RRs: 0",
        "Number of Additional RRs: 0",
        "Queries",
        "us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)",
        "Name: us.pool.ntp.org",
        "[Name Length: 17]",
        "[Label Count: 4]",
        "Type: A (IPv4 host address) (1)",
        "Class: IN (Internet) (1)",
    },

    {
        "MyDNS Protocol",
        "Transaction ID: 42",
        "Flags: 0x8180",
        "1... .... .... .... = Response: this is a response",
        "[Expert Info (Chat/Response): It's a response!]",
        "[It's a response!]",
        "[Severity level: Chat]",
        "[Group: Response]",
         ".000 0... .... .... = Opcode: 0",
        ".... .0.. .... .... = Authoritative: False",
        ".... ..0. .... .... = Truncated: False",
        ".... .... 1... .... = Recursion available: True",
        ".... .... .0.. .... = World War Z - Reserved for future use: 0x0000",
        ".... .... ..0. .... = Authenticated: no",
        ".... .... .... 0000 = Response code: No Error (0)",
        ".... .... ...0 .... = Checking disabled: False",
        "DNS answer to life, the universe, and everything",
        "[Expert Info (Note/Comment): DNS answer to life, the universe, and everything]",
        "[DNS answer to life, the universe, and everything]",
        "[Severity level: Note]",
        "[Group: Comment]",
        "Number of Questions: 1",
        "Number of Answer RRs: 15",
        "Number of Authority RRs: 6",
        "Number of Additional RRs: 2",
        "Queries",
        "us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)",
        "Name: us.pool.ntp.org",
        "[Name Length: 17]",
        "[Label Count: 4]",
        "Type: A (IPv4 host address) (1)",
        "Class: IN (Internet) (1)",
    },

    {
        "MyDNS Protocol",
        "Transaction ID: 43",
        "Flags: 0x0100",
        "0... .... .... .... = Response: this is a query",
        "[Expert Info (Chat/Request): DNS query message]",
        "[DNS query message]",
        "[Severity level: Chat]",
        "[Group: Request]",
       ".000 0... .... .... = Opcode: 0",
        ".... ..0. .... .... = Truncated: False",
        ".... ...1 .... .... = Recursion desired: yes",
        ".... .... .0.. .... = World War Z - Reserved for future use: 0x0000",
        ".... .... ...0 .... = Checking disabled: False",
        "Number of Questions: 1",
        "Number of Answer RRs: 0",
        "Number of Authority RRs: 0",
        "Number of Additional RRs: 0",
        "Queries",
        "us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)",
        "Name: us.pool.ntp.org",
        "[Name Length: 17]",
        "[Label Count: 4]",
        "Type: A (IPv4 host address) (1)",
        "Class: IN (Internet) (1)",
    },

    {
        "MyDNS Protocol",
        "Transaction ID: 43",
        "Flags: 0x8180",
        "1... .... .... .... = Response: this is a response",
        "[Expert Info (Chat/Response): It's a response!]",
        "[It's a response!]",
        "[Severity level: Chat]",
        "[Group: Response]",
         ".000 0... .... .... = Opcode: 0",
        ".... .0.. .... .... = Authoritative: False",
        ".... ..0. .... .... = Truncated: False",
        ".... .... 1... .... = Recursion available: True",
        ".... .... .0.. .... = World War Z - Reserved for future use: 0x0000",
        ".... .... ..0. .... = Authenticated: no",
        ".... .... .... 0000 = Response code: No Error (0)",
        ".... .... ...0 .... = Checking disabled: False",
        "Number of Questions: 1",
        "Number of Answer RRs: 15",
        "Number of Authority RRs: 6",
        "Number of Additional RRs: 2",
        "Queries",
        "us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)",
        "Name: us.pool.ntp.org",
        "[Name Length: 17]",
        "[Label Count: 4]",
        "Type: A (IPv4 host address) (1)",
        "Class: IN (Internet) (1)",
    },
}

-- we're going to see those two sets of output twice: both by the normal
-- dissector, then the first one by the heuristic, then the second one by
-- a conversation match
local numtests = 1 + #lines[1] + #lines[2] + #lines[3] + #lines[4]
print("going to run "..numtests.." tests")

-- for an example of what we're reading through to verify, look at end of this file
print("opening file testin.txt")
local file = io.open("testin.txt", "r")
local line = file:read()

local pktidx = 1
local total = 0
local found = false

while line do
    -- eat beginning whitespace
    line = line:gsub("^%s+","",1)
    if line:find("^Frame %d+:") then
        pktidx = line:match("^Frame (%d+):")
        testing("Frame "..pktidx)
        pktidx = tonumber(pktidx)
        if pktidx > 4 then pktidx = pktidx - 4 end
        line = file:read()
    elseif line:find("%[Heuristic dissector used%]") then
        -- start again, because it now repeats
        -- but we should not see this [Heuristic dissector used] line again
        -- or it's an error in setting the conversation
        if found then
            error("Heuristic dissector ran twice - conversation setting not working?")
            return
        end
        found = true
        total = total + 1
        line = file:read()
    elseif line == lines[pktidx][1] then
        -- we've matched the first line of our section
        -- now verify the rest is sequential
        for i, v in ipairs(lines[pktidx]) do
            io.stdout:write("testing Frame "..pktidx..", line "..i.."...")
            if not line then
                -- ended too soon
                io.stdout:write("failed!\n")
                error("Ran out of file lines!")
                return
            end
            -- eat beginning whitespace
            line = line:gsub("^%s+","",1)
            if line ~= v then
                io.stdout:write("failed!\n")
                print("Got this:'"..line.."', expected this:'"..v.."'")
                error("mismatched lines!")
                return
            end
            io.stdout:write("passed\n")
            total = total + 1
            line = file:read()
        end
    else
        line = file:read()
    end
end

print(total.." of "..numtests.." tests run and passed")

if total ~= numtests then
    error("Did not find all our lines to test!")
    return
end

print("\n-----------------------------\n")
-- must print out the following for success (the test shell sciprt looks for this)
print("All tests passed!\n\n")


----------------------------------------------------------
-- We should see something like this:
--[[
Frame 1: 75 bytes on wire (600 bits), 75 bytes captured (600 bits)
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep 26, 2004 23:18:04.938672000 EDT
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1096255084.938672000 seconds
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 75 bytes (600 bits)
    Capture Length: 75 bytes (600 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:mydns]
Ethernet II, Src: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e), Dst: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53)
    Destination: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53)
        Address: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e)
        Address: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IP (0x0800)
Internet Protocol Version 4, Src: 192.168.50.50 (192.168.50.50), Dst: 192.168.0.1 (192.168.0.1)
    Version: 4
    Header Length: 20 bytes
    Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport))
        0000 00.. = Differentiated Services Codepoint: Default (0x00)
        .... ..00 = Explicit Congestion Notification: Not-ECT (Not ECN-Capable Transport) (0x00)
    Total Length: 61
    Identification: 0x0a41 (2625)
    Flags: 0x00
        0... .... = Reserved bit: Not set
        .0.. .... = Don't fragment: Not set
        ..0. .... = More fragments: Not set
    Fragment offset: 0
    Time to live: 128
    Protocol: UDP (17)
    Header checksum: 0x7ceb [correct]
        [Good: True]
        [Bad: False]
    Source: 192.168.50.50 (192.168.50.50)
    Destination: 192.168.0.1 (192.168.0.1)
User Datagram Protocol, Src Port: 65282 (65282), Dst Port: 65333 (65333)
    Source Port: 65282 (65282)
    Destination Port: 65333 (65333)
    Length: 41
    Checksum: 0x07a9 [validation disabled]
        [Good Checksum: False]
        [Bad Checksum: False]
    [Stream index: 0]
MyDNS Protocol
    Transaction ID: 43
    Flags: 0x0100
        0... .... .... .... = Response: this is a query
        .000 0... .... .... = Opcode: 0
        .... ..0. .... .... = Truncated: False
        .... ...1 .... .... = Recursion desired: yes
        .... .... .0.. .... = World War Z - Reserved for future use: 0x0000
        .... .... ...0 .... = Checking disabled: False
    Number of Questions: 1
    Number of Answer RRs: 0
    Number of Authority RRs: 0
    Number of Additional RRs: 0
    Queries
        us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)
            Name: us.pool.ntp.org
            [Name Length: 17]
            [Label Count: 4]
            Type: A (IPv4 host address) (1)
            Class: IN (Internet) (1)

Frame 2: 540 bytes on wire (4320 bits), 540 bytes captured (4320 bits)
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep 26, 2004 23:18:04.945618000 EDT
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1096255084.945618000 seconds
    [Time delta from previous captured frame: 0.006946000 seconds]
    [Time delta from previous displayed frame: 0.006946000 seconds]
    [Time since reference or first frame: 0.006946000 seconds]
    Frame Number: 2
    Frame Length: 540 bytes (4320 bits)
    Capture Length: 540 bytes (4320 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:mydns]
Ethernet II, Src: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53), Dst: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e)
    Destination: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e)
        Address: AmbitMic_6c:40:4e (00:d0:59:6c:40:4e)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53)
        Address: Cisco-Li_82:b2:53 (00:0c:41:82:b2:53)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IP (0x0800)
Internet Protocol Version 4, Src: 192.168.0.1 (192.168.0.1), Dst: 192.168.50.50 (192.168.50.50)
    Version: 4
    Header Length: 20 bytes
    Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport))
        0000 00.. = Differentiated Services Codepoint: Default (0x00)
        .... ..00 = Explicit Congestion Notification: Not-ECT (Not ECN-Capable Transport) (0x00)
    Total Length: 526
    Identification: 0x2153 (8531)
    Flags: 0x00
        0... .... = Reserved bit: Not set
        .0.. .... = Don't fragment: Not set
        ..0. .... = More fragments: Not set
    Fragment offset: 0
    Time to live: 63
    Protocol: UDP (17)
    Header checksum: 0xa508 [correct]
        [Good: True]
        [Bad: False]
    Source: 192.168.0.1 (192.168.0.1)
    Destination: 192.168.50.50 (192.168.50.50)
User Datagram Protocol, Src Port: 65333 (65333), Dst Port: 65282 (65282)
    Source Port: 65333 (65333)
    Destination Port: 65282 (65282)
    Length: 506
    Checksum: 0xf9d5 [validation disabled]
        [Good Checksum: False]
        [Bad Checksum: False]
    [Stream index: 0]
MyDNS Protocol
    Transaction ID: 43
    Flags: 0x8180
        1... .... .... .... = Response: this is a response
        .000 0... .... .... = Opcode: 0
        .... .0.. .... .... = Authoritative: False
        .... ..0. .... .... = Truncated: False
        .... .... 1... .... = Recursion available: True
        .... .... .0.. .... = World War Z - Reserved for future use: 0x0000
        .... .... ..0. .... = Authenticated: no
        .... .... .... 0000 = Response code: No Error (0)
        .... .... ...0 .... = Checking disabled: False
    Number of Questions: 1
    Number of Answer RRs: 15
    Number of Authority RRs: 6
    Number of Additional RRs: 2
    Queries
        us.pool.ntp.org: type A (IPv4 host address) (1), class IN (Internet) (1)
            Name: us.pool.ntp.org
            [Name Length: 17]
            [Label Count: 4]
            Type: A (IPv4 host address) (1)
            Class: IN (Internet) (1)
]]

