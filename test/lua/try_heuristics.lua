-- Define a new protocol that runs TCP heuristics and on failure runs UDP heuristics
--
-- This expects to be run against dns_port.pcap, so it should end up resolving all packets to DNS with the UDP heuristic
local test_proto = Proto("test", "Test Protocol")

-- Have all tests passed so far?
-- Anything that fails should set this to false, which will suppress the "".
all_ok = true

-- The number of frames expected
-- Final test status is output with last frame
LAST_FRAME = 4

function test_proto.dissector(buf, pinfo, root)
    print("Dissector function run")

    orig_proto_name = tostring(pinfo.cols.protocol)

    -- Run TCP heuristic dissectors
    -- Dissection should fail, and the protocol name should be unchanged
    tcp_success = DissectorTable.try_heuristics("tcp", buf, pinfo, root)
    curr_proto_name = tostring(pinfo.cols.protocol)

    if tcp_success then
        all_ok = false
        print("tcp heuristics were not expected to report success, but did!")
    end

    if curr_proto_name ~= orig_proto_name then
        all_ok = false
        print("after tcp heuristics were run, protocol " .. orig_proto_name .. " was not expected to change, but became " .. curr_proto_name .. "!")
    end

    -- Run UDP heuristic dissectors
    -- Dissection should succeed, and the protocol name should be changed to DNS
    udp_success = DissectorTable.try_heuristics("udp", buf, pinfo, root)
    curr_proto_name = tostring(pinfo.cols.protocol)

    if not udp_success then
        all_ok = false
        print("udp heuristics were expected to report success, but did not!")
    end

    if curr_proto_name ~= "DNS" then
        all_ok = false
        print("after udp heuristics were run, protocol should be changed to DNS, but became " .. curr_proto_name .. "!")
    end

    -- If we're on the last frame, report success or failure
    if pinfo.number == LAST_FRAME then
        if all_ok then
            print("All tests passed!")
        else
            print("Some tests failed!")
        end
    end
end

-- Invoke test_proto on the expected UDP traffic
DissectorTable.get("udp.port"):add(65333, test_proto)
DissectorTable.get("udp.port"):add(65346, test_proto)
