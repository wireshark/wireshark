-- test script for field extractors in a postdissector on the first
-- of two passes
-- use with dhcp.pcap in test/captures directory

local proto  = Proto("test_postdissector", "Test Postdissector")
local f_seen = ProtoField.uint32("test_postdissector.seen",
                                 "UDP frames seen on the first pass")
proto.fields = { f_seen }
local f_port = Field.new("udp.srcport")
local seen   = {}
local count  = 0

function proto.init()
    seen  = {}
    count = 0
end

function proto.dissector(tvb, pinfo, tree)
    if not pinfo.visited and f_port() then
        count = count + 1
        seen[pinfo.number] = count
    end

    if seen[pinfo.number] then
        tree:add(proto):add(f_seen, seen[pinfo.number])
    end
end

register_postdissector(proto)
