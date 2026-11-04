----------------------------------------
-- script-name: ax25_stream.lua
-- A Lua subdissector of AX.25 sees the stream index and the link
-- conversation. Run with ax25_sabm.pcap.gz: frames 4 and 6 are I frames
-- of stream 0, frame 10 a UI frame (no stream) on the same link, frame 13
-- an I frame of stream 1.
----------------------------------------

local testlib = require("testlib")

local FRAME = "frame"
local OTHER = "other"

testlib.init({
    [FRAME] = 4,
    [OTHER] = 11,
})

local f_stream = Field.new("ax25.stream")

local ax25_lua = Proto("ax25_lua", "AX.25 Lua subdissector test")

local numinits = 0
function ax25_lua.init()
    numinits = numinits + 1
    if numinits == 2 then
        testlib.getResults()
    end
end

local stream0_conv = nil

function ax25_lua.dissector(tvb, pinfo, tree)
    testlib.countPacket(FRAME)
    local stream = f_stream()
    local conv = pinfo.conversation

    if pinfo.number == 4 then
        testlib.test(OTHER, "frame 4: ax25.stream == 0", stream ~= nil and stream.value == 0)
        testlib.test(OTHER, "frame 4: conversation type",
            string.find(tostring(conv), "type=AX25", 1, true) ~= nil)
        testlib.test(OTHER, "frame 4: conversation stations",
            string.find(tostring(conv), "N7LEM", 1, true) ~= nil and
            string.find(tostring(conv), "NJ7P", 1, true) ~= nil)
        stream0_conv = conv
        conv[ax25_lua] = 1
    elseif pinfo.number == 6 then
        testlib.test(OTHER, "frame 6: ax25.stream == 0", stream ~= nil and stream.value == 0)
        testlib.test(OTHER, "frame 6: same conversation", conv == stream0_conv)
        testlib.test(OTHER, "frame 6: conversation data kept", conv[ax25_lua] == 1)
    elseif pinfo.number == 10 then
        testlib.test(OTHER, "frame 10: UI frame has no ax25.stream", stream == nil)
        testlib.test(OTHER, "frame 10: still the link's conversation", conv == stream0_conv)
    elseif pinfo.number == 13 then
        testlib.test(OTHER, "frame 13: ax25.stream == 1", stream ~= nil and stream.value == 1)
        testlib.test(OTHER, "frame 13: a new conversation", conv ~= stream0_conv)
        testlib.test(OTHER, "frame 13: no data from stream 0", conv[ax25_lua] == nil)
    end
    -- Called once for each of the 4 PID 0xF0 frames
    testlib.pass(FRAME)
end

DissectorTable.get("ax25.pid"):add(0xF0, ax25_lua)
