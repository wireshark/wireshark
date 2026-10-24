----------------------------------------
-- script-name: conversation_expiry.lua
-- Test that Conversation objects expire when the file scope is freed.
-- Run with tshark -M 2, which resets the session (freeing the file scope,
-- and so all conversations) after every two packets.
----------------------------------------

local testlib = require("testlib")

local OTHER = "other"

-- Packets 2 and 4 are in the same session as the packet before them,
-- packet 3 is after a reset.
testlib.init({ [OTHER] = 4 + 7 + 4 })

local test_proto = Proto("conv_expiry", "Conversation expiry test")

local n = 0
local saved

local function check_valid(c, data)
    -- The format of %p is platform dependent (no 0x prefix on Windows).
    local s = tostring(c)
    testlib.test(OTHER, "tostring", string.match(s, "^Conversation object %(.+%)$") ~= nil and s ~= "Conversation object (expired)")
    testlib.test(OTHER, "index", c[test_proto] == data)
    testlib.test(OTHER, "eq", pcall(function() return c == Conversation.find_by_id(0, convtypes.UDP, 7) end))
    testlib.test(OTHER, "newindex", pcall(function() c[test_proto] = data end))
end

local function check_expired(c)
    testlib.test(OTHER, "expired tostring", tostring(c) == "Conversation object (expired)")
    testlib.test(OTHER, "expired index", not pcall(function() return c[test_proto] end))
    testlib.test(OTHER, "expired newindex", not pcall(function() c[test_proto] = {} end))
    testlib.test(OTHER, "expired eq", not pcall(function() return c == Conversation.find_by_id(0, convtypes.UDP, 7) end))
    testlib.test(OTHER, "expired dissector", not pcall(function() c.dissector = test_proto end))
    local ok, err = pcall(function() return c[test_proto] end)
    testlib.test(OTHER, "expired error", not ok and string.find(err, "expired Conversation") ~= nil)
end

function test_proto.dissector(tvb, pinfo, tree)
    n = n + 1
    local c = Conversation.find_by_id(0, convtypes.UDP, 7)
    if n == 1 or n == 3 then
        if n == 3 then
            check_expired(saved.conv)
            -- The new conversation has no data from before the reset.
            testlib.test(OTHER, "new conversation data", c[test_proto] == nil)
        end
        saved = { conv = c, data = { n } }
        c[test_proto] = saved.data
    else
        check_valid(saved.conv, saved.data)
    end
end
register_postdissector(test_proto)

local tap = Listener.new()
function tap.draw()
    testlib.getResults()
end
