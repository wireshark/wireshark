----------------------------------------
-- script-name: listener_expiry.lua
-- Test that per-packet objects kept from a Listener's packet() callback
-- expire at the end of the packet, even if no Lua dissector is called.
-- Run on dhcp.pcap (4 packets).
----------------------------------------

local testlib = require("testlib")

local OTHER = "other"

-- Two valid checks in each of the 4 packets, two expired checks in the
-- last 3 packets, and two expired checks in draw().
testlib.init({ [OTHER] = 4 * 2 + 3 * 2 + 2 })

local ip_src = Field.new("ip.src")

local saved_range
local saved_fi

local function expired(f)
    local ok, err = pcall(f)
    return not ok and string.find(tostring(err), "expired") ~= nil
end

local function check_expired(where)
    testlib.test(OTHER, "TvbRange expired " .. where,
        expired(function() return saved_range:uint() end))
    testlib.test(OTHER, "FieldInfo expired " .. where,
        expired(function() return saved_fi.value end))
end

local tap = Listener.new("frame")

function tap.packet(pinfo, tvb)
    if saved_range then
        check_expired("in a later packet")
    end
    saved_range = tvb(0, 4)
    saved_fi = ip_src()
    testlib.test(OTHER, "TvbRange valid", pcall(function() return saved_range:uint() end))
    testlib.test(OTHER, "FieldInfo valid", saved_fi ~= nil and pcall(function() return saved_fi.value end))
end

function tap.draw()
    check_expired("in draw")
    testlib.getResults()
end
