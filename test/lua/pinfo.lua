-- test script for Pinfo and Address functions
-- use with dhcp.pcap in test/captures directory

------------- general test helper funcs ------------
local testlib = require("testlib")
local FRAME = "frame"
local DENIED = "denied"
local GETTER = "getter"
local SETTER = "setter"
local ADDR = "address"
local OTHER = "other"

-- expected number of runs per type
local n_frames = 4
local taptests = {
    [FRAME]=n_frames,
    [DENIED]=n_frames*32,
    [GETTER]=n_frames*39,
    [SETTER]=n_frames*16,
    [ADDR]=n_frames*6,
    [OTHER]=n_frames*2,
}
testlib.init(taptests)

---------
-- the following are so we can use pcall (which needs a function to call)
local function setPinfo(pinfo,name,value)
    pinfo[name] = value
end

local function getPinfo(pinfo,name)
    local foo = pinfo[name]
end

------------- test script ------------


local tap = Listener.new()


function tap.packet(pinfo,tvb)
    testlib.countPacket(FRAME)
    testlib.testing(FRAME,"Pinfo in Frame")

    testlib.test(OTHER,"typeof-1", typeof(pinfo) == "Pinfo")

    testlib.test(OTHER,"tostring-1", tostring(pinfo) == "a Pinfo")

    testlib.testing(FRAME,"negative tests")

    -- try to set read-only attributes
    testlib.test(DENIED,"Pinfo.number-set-1",not pcall(setPinfo,pinfo,"number",0))
    testlib.test(DENIED,"Pinfo.len-set-1",not pcall(setPinfo,pinfo,"len",0))
    testlib.test(DENIED,"Pinfo.caplen-set-1",not pcall(setPinfo,pinfo,"caplen",0))
    testlib.test(DENIED,"Pinfo.rel_ts-set-1",not pcall(setPinfo,pinfo,"rel_ts",0))
    testlib.test(DENIED,"Pinfo.delta_ts-set-1",not pcall(setPinfo,pinfo,"delta_ts",0))
    testlib.test(DENIED,"Pinfo.delta_dis_ts-set-1",not pcall(setPinfo,pinfo,"delta_dis_ts",0))
    testlib.test(DENIED,"Pinfo.visited-set-1",not pcall(setPinfo,pinfo,"visited",0))
    testlib.test(DENIED,"Pinfo.lo-set-1",not pcall(setPinfo,pinfo,"lo",0))
    testlib.test(DENIED,"Pinfo.hi-set-1",not pcall(setPinfo,pinfo,"hi",0))
    testlib.test(DENIED,"Pinfo.match-set-1",not pcall(setPinfo,pinfo,"match",0))
    testlib.test(DENIED,"Pinfo.curr_proto-set-1",not pcall(setPinfo,pinfo,"curr_proto",0))
    testlib.test(DENIED,"Pinfo.columns-set-1",not pcall(setPinfo,pinfo,"columns",0))
    testlib.test(DENIED,"Pinfo.cols-set-1",not pcall(setPinfo,pinfo,"cols",0))
    testlib.test(DENIED,"Pinfo.private-set-1",not pcall(setPinfo,pinfo,"private",0))
    testlib.test(DENIED,"Pinfo.fragmented-set-1",not pcall(setPinfo,pinfo,"fragmented",0))
    testlib.test(DENIED,"Pinfo.in_error_pkt-set-1",not pcall(setPinfo,pinfo,"in_error_pkt",0))
    testlib.test(DENIED,"Pinfo.match_uint-set-1",not pcall(setPinfo,pinfo,"match_uint",0))
    testlib.test(DENIED,"Pinfo.match_string-set-1",not pcall(setPinfo,pinfo,"match_string",0))

    -- wrong type being set
    testlib.test(DENIED,"Pinfo.src-set-1",not pcall(setPinfo,pinfo,"src","foobar"))
    testlib.test(DENIED,"Pinfo.dst-set-1",not pcall(setPinfo,pinfo,"dst","foobar"))
    testlib.test(DENIED,"Pinfo.dl_src-set-1",not pcall(setPinfo,pinfo,"dl_src","foobar"))
    testlib.test(DENIED,"Pinfo.dl_dst-set-1",not pcall(setPinfo,pinfo,"dl_dst","foobar"))
    testlib.test(DENIED,"Pinfo.net_src-set-1",not pcall(setPinfo,pinfo,"net_src","foobar"))
    testlib.test(DENIED,"Pinfo.net_dst-set-1",not pcall(setPinfo,pinfo,"net_dst","foobar"))
    testlib.test(DENIED,"Pinfo.port_type-set-1",not pcall(setPinfo,pinfo,"port_type","foobar"))
    testlib.test(DENIED,"Pinfo.src_port-set-1",not pcall(setPinfo,pinfo,"src_port","foobar"))
    testlib.test(DENIED,"Pinfo.dst_port-set-1",not pcall(setPinfo,pinfo,"dst_port","foobar"))
    testlib.test(DENIED,"Pinfo.can_desegment-set-1",not pcall(setPinfo,pinfo,"can_desegment","foobar"))
    testlib.test(DENIED,"Pinfo.desegment_len-set-1",not pcall(setPinfo,pinfo,"desegment_len","foobar"))
    testlib.test(DENIED,"Pinfo.desegment_offset-set-1",not pcall(setPinfo,pinfo,"desegment_offset","foobar"))

    -- invalid attribute names
    testlib.test(DENIED,"Pinfo.set-1",not pcall(setPinfo,pinfo,"foobar","foobar"))
    testlib.test(DENIED,"Pinfo.get-12",not pcall(getPinfo,pinfo,"foobar"))

    testlib.testing(FRAME,"basic getter tests")

    local pktlen, srcip, dstip, srcport, dstport

    if pinfo.number == 1 or pinfo.number == 3 then
        pktlen = 314
        srcip = "0.0.0.0"
        dstip = "255.255.255.255"
        srcport = 68
        dstport = 67
    else
        pktlen = 342
        srcip = "192.168.0.1"
        dstip = "192.168.0.10"
        srcport = 67
        dstport = 68
    end

    testlib.test(GETTER,"Pinfo.number-get-1",pinfo.number == testlib.getPktCount(FRAME))
    testlib.test(GETTER,"Pinfo.len-get-1",pinfo.len == pktlen)
    testlib.test(GETTER,"Pinfo.caplen-get-1",pinfo.caplen == pktlen)
    testlib.test(GETTER,"Pinfo.visited-get-1",pinfo.visited == true)
    testlib.test(GETTER,"Pinfo.lo-get-1",tostring(pinfo.lo) == srcip)
    testlib.test(GETTER,"Pinfo.lo-get-2",typeof(pinfo.lo) == "Address")
    testlib.test(GETTER,"Pinfo.hi-get-1",tostring(pinfo.hi) == dstip)
    testlib.test(GETTER,"Pinfo.hi-get-2",typeof(pinfo.hi) == "Address")
    testlib.test(GETTER,"Pinfo.port_type-get-1",pinfo.port_type == 3)
    testlib.test(GETTER,"Pinfo.match-get-1",pinfo.match == 0)
    testlib.test(GETTER,"Pinfo.curr_proto-get-1",tostring(pinfo.curr_proto) == "<Missing Protocol Name>")
    testlib.test(GETTER,"Pinfo.columns-get-1",tostring(pinfo.columns) == "Columns")
    testlib.test(GETTER,"Pinfo.columns-get-2",typeof(pinfo.columns) == "Columns")
    testlib.test(GETTER,"Pinfo.cols-get-1",tostring(pinfo.cols) == "Columns")
    testlib.test(GETTER,"Pinfo.cols-get-2",typeof(pinfo.cols) == "Columns")
    testlib.test(GETTER,"Pinfo.private-get-1",type(pinfo.private) == "userdata")
    testlib.test(GETTER,"Pinfo.fragmented-get-1",pinfo.fragmented == false)

    testlib.test(GETTER,"Pinfo.in_error_pkt-get-1",pinfo.in_error_pkt == false)
    testlib.test(GETTER,"Pinfo.match_uint-get-1",pinfo.match_uint == 0)
    testlib.test(GETTER,"Pinfo.match_string-get-1",pinfo.match_string == nil)

    testlib.test(GETTER,"Pinfo.src-get-1",tostring(pinfo.src) == srcip)
    testlib.test(GETTER,"Pinfo.src-get-2",typeof(pinfo.src) == "Address")
    testlib.test(GETTER,"Pinfo.dst-get-1",tostring(pinfo.dst) == dstip)
    testlib.test(GETTER,"Pinfo.dst-get-2",typeof(pinfo.dst) == "Address")

    testlib.test(GETTER,"Pinfo.dl_src-get-1",typeof(pinfo.dl_src) == "Address")
    testlib.test(GETTER,"Pinfo.dl_dst-get-1",typeof(pinfo.dl_dst) == "Address")
    testlib.test(GETTER,"Pinfo.net_src-get-1",tostring(pinfo.net_src) == srcip)
    testlib.test(GETTER,"Pinfo.net_src-get-2",typeof(pinfo.net_src) == "Address")
    testlib.test(GETTER,"Pinfo.net_dst-get-1",tostring(pinfo.net_dst) == dstip)
    testlib.test(GETTER,"Pinfo.net_dst-get-2",typeof(pinfo.net_dst) == "Address")
    testlib.test(GETTER,"Pinfo.src_port-get-1",pinfo.src_port == srcport)
    testlib.test(GETTER,"Pinfo.dst_port-get-1",pinfo.dst_port == dstport)
    testlib.test(GETTER,"Pinfo.can_desegment-get-1",pinfo.can_desegment == 0)
    testlib.test(GETTER,"Pinfo.desegment_len-get-1",pinfo.desegment_len == 0)
    testlib.test(GETTER,"Pinfo.desegment_offset-get-1",pinfo.desegment_offset == 0)

    testlib.test(GETTER,"pinfo.p2p_dir", pinfo.p2p_dir == P2P_DIR_UNKNOWN)

    if pinfo.number == 1 then
        testlib.test(GETTER,"Pinfo.rel_ts-get-1",pinfo.rel_ts == 0)
        testlib.test(GETTER,"Pinfo.delta_ts-get-1",pinfo.delta_ts == 0)
        testlib.test(GETTER,"Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0)
    elseif pinfo.number == 2 then
        testlib.test(GETTER,"Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.000295)
        testlib.test(GETTER,"Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.000295)
        testlib.test(GETTER,"Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.000295)
    elseif pinfo.number == 3 then
        testlib.test(GETTER,"Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.070031)
        testlib.test(GETTER,"Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.069736)
        testlib.test(GETTER,"Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.069736)
    elseif pinfo.number == 4 then
        testlib.test(GETTER,"Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.070345)
        testlib.test(GETTER,"Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.000314)
        testlib.test(GETTER,"Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.000314)
    end


    testlib.testing(FRAME,"basic setter tests")

    local tmp = pinfo.src
    pinfo.src = pinfo.dst
    pinfo.dst = tmp
    testlib.test(SETTER,"Pinfo.src-set-1",tostring(pinfo.src) == dstip)
    testlib.test(SETTER,"Pinfo.src-set-1",typeof(pinfo.src) == "Address")
    testlib.test(SETTER,"Pinfo.dst-set-1",tostring(pinfo.dst) == srcip)
    testlib.test(SETTER,"Pinfo.dst-set-1",typeof(pinfo.dst) == "Address")

    local dl_dst_val = tostring(pinfo.dl_dst)
    local dl_src_val = tostring(pinfo.dl_src)
    tmp = pinfo.dl_src
    pinfo.dl_src = pinfo.dl_dst
    pinfo.dl_dst = tmp
    testlib.test(SETTER,"Pinfo.dl_src-set-1",tostring(pinfo.dl_src) == dl_dst_val)
    testlib.test(SETTER,"Pinfo.dl_dst-set-1",tostring(pinfo.dl_dst) == dl_src_val)

    tmp = pinfo.net_src
    pinfo.net_src = pinfo.net_dst
    pinfo.net_dst = tmp
    testlib.test(SETTER,"Pinfo.net_src-set-1",tostring(pinfo.net_src) == dstip)
    testlib.test(SETTER,"Pinfo.net_src-set-1",typeof(pinfo.net_src) == "Address")
    testlib.test(SETTER,"Pinfo.net_dst-set-1",tostring(pinfo.net_dst) == srcip)
    testlib.test(SETTER,"Pinfo.net_dst-set-1",typeof(pinfo.net_dst) == "Address")

    pinfo.port_type = 2
    testlib.test(SETTER,"Pinfo.port_type-set-1",pinfo.port_type == 2)

    tmp = pinfo.src_port
    pinfo.src_port = pinfo.dst_port
    pinfo.dst_port = tmp
    testlib.test(SETTER,"Pinfo.src_port-set-1",pinfo.src_port == dstport)
    testlib.test(SETTER,"Pinfo.dst_port-set-1",pinfo.dst_port == srcport)

    pinfo.can_desegment = 12
    testlib.test(SETTER,"Pinfo.can_desegment-set-1",pinfo.can_desegment == 12)
    pinfo.desegment_len = 34
    testlib.test(SETTER,"Pinfo.desegment_len-set-1",pinfo.desegment_len == 34)
    pinfo.desegment_offset = 45
    testlib.test(SETTER,"Pinfo.desegment_offset-set-1",pinfo.desegment_offset == 45)

    testlib.testing(FRAME,"Address functions")
    testlib.test(ADDR,"Address-eq-1", pinfo.lo == pinfo.dst)
    testlib.test(ADDR,"Address-eq-2", pinfo.lo ~= pinfo.hi)
    testlib.test(ADDR,"Address-lt-1", pinfo.lo < pinfo.hi)
    testlib.test(ADDR,"Address-lt-2", pinfo.hi > pinfo.lo)
    testlib.test(ADDR,"Address-le-1", pinfo.lo <= pinfo.hi)
    testlib.test(ADDR,"Address-le-2", pinfo.lo <= pinfo.dst)

    testlib.pass(FRAME)

end

function tap.draw()
    testlib.getResults()
end
