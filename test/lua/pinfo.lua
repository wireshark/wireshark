-- test script for Pinfo and Address functions
-- use with dhcp.pcap in test/captures directory

local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major then
    major = tonumber(major)
    minor = tonumber(minor)
    micro = tonumber(micro)
else
    major = 99
    minor = 99
    micro = 99
end

------------- general test helper funcs ------------
local FRAME = "frame"
local OTHER = "other"

local packet_counts = {}
local function incPktCount(name)
    if not packet_counts[name] then
        packet_counts[name] = 1
    else
        packet_counts[name] = packet_counts[name] + 1
    end
end
local function getPktCount(name)
    return packet_counts[name] or 0
end

local passed = {}
local function setPassed(name)
    if not passed[name] then
        passed[name] = 1
    else
        passed[name] = passed[name] + 1
    end
end

-- expected number of runs per type
-- note ip only runs 3 times because it gets removed
-- and bootp only runs twice because the filter makes it run
-- once and then it gets replaced with a different one for the second time
local taptests = { [FRAME]=4, [OTHER]=0 }
local function getResults()
    print("\n-----------------------------\n")
    for k,v in pairs(taptests) do
        if v ~= 0 and passed[k] ~= v then
            print("Something didn't run or ran too much... tests failed!")
            print("Listener type "..k.." expected: "..v..", but got: "..tostring(passed[k]))
            return false
        end
    end
    print("All tests passed!\n\n")
    return true
end


local function testing(type,...)
    print("---- Testing "..type.." ---- "..tostring(...).." for packet # "..getPktCount(type).." ----")
end

local function test(type,name, ...)
    io.stdout:write("test "..type.."-->"..name.."-"..getPktCount(type).."...")
    if (...) == true then
        io.stdout:write("passed\n")
        return true
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

---------
-- the following are so we can use pcall (which needs a function to call)
local function setPinfo(pinfo,name,value)
    pinfo[name] = value
end

local function getPinfo(pinfo,name)
    local foo = pinfo[name]
end

------------- test script ------------

----------------------------------
-- modify original test function, kinda sorta
local orig_test = test
test = function (...)
    return orig_test(FRAME,...)
end


local tap = Listener.new()


function tap.packet(pinfo,tvb)
    incPktCount(FRAME)
    testing(FRAME,"Pinfo in Frame")

    test("typeof-1", typeof(pinfo) == "Pinfo")

    test("tostring-1", tostring(pinfo) == "a Pinfo")

    testing(FRAME,"negative tests")

    -- try to set read-only attributes
--[[
these tests *should* ALL pass, but currently pinfo read-only members
silently accept being set (though nothing happens) Blech!!
    test("Pinfo.number-set-1",not pcall(setPinfo,pinfo,"number",0))
    test("Pinfo.len-set-1",not pcall(setPinfo,pinfo,"len",0))
    test("Pinfo.caplen-set-1",not pcall(setPinfo,pinfo,"caplen",0))
    test("Pinfo.rel_ts-set-1",not pcall(setPinfo,pinfo,"rel_ts",0))
    test("Pinfo.delta_ts-set-1",not pcall(setPinfo,pinfo,"delta_ts",0))
    test("Pinfo.delta_dis_ts-set-1",not pcall(setPinfo,pinfo,"delta_dis_ts",0))
    test("Pinfo.visited-set-1",not pcall(setPinfo,pinfo,"visited",0))
    test("Pinfo.lo-set-1",not pcall(setPinfo,pinfo,"lo",0))
    test("Pinfo.hi-set-1",not pcall(setPinfo,pinfo,"hi",0))
    test("Pinfo.port_type-set-1",not pcall(setPinfo,pinfo,"port_type",0))
    test("Pinfo.ipproto-set-1",not pcall(setPinfo,pinfo,"ipproto",0))
    test("Pinfo.match-set-1",not pcall(setPinfo,pinfo,"match",0))
    test("Pinfo.curr_proto-set-1",not pcall(setPinfo,pinfo,"curr_proto",0))
    test("Pinfo.columns-set-1",not pcall(setPinfo,pinfo,"columns",0))
    test("Pinfo.cols-set-1",not pcall(setPinfo,pinfo,"cols",0))
    test("Pinfo.private_data-set-1",not pcall(setPinfo,pinfo,"private_data",0))
    test("Pinfo.private-set-1",not pcall(setPinfo,pinfo,"private",0))
    test("Pinfo.fragmented-set-1",not pcall(setPinfo,pinfo,"fragmented",0))
    test("Pinfo.in_error_pkt-set-1",not pcall(setPinfo,pinfo,"in_error_pkt",0))
    test("Pinfo.match_uint-set-1",not pcall(setPinfo,pinfo,"match_uint",0))
    test("Pinfo.match_string-set-1",not pcall(setPinfo,pinfo,"match_string",0))
]]

    -- wrong type being set
    test("Pinfo.src-set-1",not pcall(setPinfo,pinfo,"src","foobar"))
    test("Pinfo.dst-set-1",not pcall(setPinfo,pinfo,"dst","foobar"))
    test("Pinfo.dl_src-set-1",not pcall(setPinfo,pinfo,"dl_src","foobar"))
    test("Pinfo.dl_dst-set-1",not pcall(setPinfo,pinfo,"dl_dst","foobar"))
    test("Pinfo.net_src-set-1",not pcall(setPinfo,pinfo,"net_src","foobar"))
    test("Pinfo.net_dst-set-1",not pcall(setPinfo,pinfo,"net_dst","foobar"))
    test("Pinfo.src_port-set-1",not pcall(setPinfo,pinfo,"src_port","foobar"))
    test("Pinfo.dst_port-set-1",not pcall(setPinfo,pinfo,"dst_port","foobar"))
    test("Pinfo.circuit_id-set-1",not pcall(setPinfo,pinfo,"circuit_id","foobar"))
    if major > 1 or minor > 10 then
        test("Pinfo.can_desegment-set-1",not pcall(setPinfo,pinfo,"can_desegment","foobar"))
    end
    test("Pinfo.desegment_len-set-1",not pcall(setPinfo,pinfo,"desegment_len","foobar"))
    test("Pinfo.desegment_offset-set-1",not pcall(setPinfo,pinfo,"desegment_offset","foobar"))

    -- invalid attribute names
--[[
again, these *should* pass, but Pinfo silently allows it!
    test("Pinfo.set-1",not pcall(setPinfo,pinfo,"foobar","foobar"))
    test("Pinfo.get-12",not pcall(getPinfo,pinfo,"foobar"))
]]

    testing(FRAME,"basic getter tests")

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

    test("Pinfo.number-get-1",pinfo.number == getPktCount(FRAME))
    test("Pinfo.len-get-1",pinfo.len == pktlen)
    test("Pinfo.caplen-get-1",pinfo.caplen == pktlen)
    test("Pinfo.visited-get-1",pinfo.visited == true)
    test("Pinfo.lo-get-1",tostring(pinfo.lo) == srcip)
    test("Pinfo.lo-get-2",typeof(pinfo.lo) == "Address")
    test("Pinfo.hi-get-1",tostring(pinfo.hi) == dstip)
    test("Pinfo.hi-get-2",typeof(pinfo.hi) == "Address")
    test("Pinfo.port_type-get-1",pinfo.port_type == 3)
    test("Pinfo.ipproto-get-1",pinfo.ipproto == 17)
    test("Pinfo.match-get-1",pinfo.match == 0)
    test("Pinfo.curr_proto-get-1",tostring(pinfo.curr_proto) == "<Missing Protocol Name>")
    test("Pinfo.columns-get-1",tostring(pinfo.columns) == "Columns")
    test("Pinfo.columns-get-2",typeof(pinfo.columns) == "Columns")
    test("Pinfo.cols-get-1",tostring(pinfo.cols) == "Columns")
    test("Pinfo.cols-get-2",typeof(pinfo.cols) == "Columns")
    test("Pinfo.private_data-get-1",type(pinfo.private_data) == "userdata")
    test("Pinfo.private-get-1",type(pinfo.private) == "userdata")
    test("Pinfo.fragmented-get-1",pinfo.fragmented == false)

    test("Pinfo.in_error_pkt-get-1",pinfo.in_error_pkt == false)
    test("Pinfo.match_uint-get-1",pinfo.match_uint == 0)
    test("Pinfo.match_string-get-1",pinfo.match_string == nil)

    test("Pinfo.src-get-1",tostring(pinfo.src) == srcip)
    test("Pinfo.src-get-2",typeof(pinfo.src) == "Address")
    test("Pinfo.dst-get-1",tostring(pinfo.dst) == dstip)
    test("Pinfo.dst-get-2",typeof(pinfo.dst) == "Address")

    test("Pinfo.dl_src-get-1",typeof(pinfo.dl_src) == "Address")
    test("Pinfo.dl_dst-get-1",typeof(pinfo.dl_dst) == "Address")
    test("Pinfo.net_src-get-1",tostring(pinfo.net_src) == srcip)
    test("Pinfo.net_src-get-2",typeof(pinfo.net_src) == "Address")
    test("Pinfo.net_dst-get-1",tostring(pinfo.net_dst) == dstip)
    test("Pinfo.net_dst-get-2",typeof(pinfo.net_dst) == "Address")
    test("Pinfo.src_port-get-1",pinfo.src_port == srcport)
    test("Pinfo.dst_port-get-1",pinfo.dst_port == dstport)
    test("Pinfo.circuit_id-get-1",pinfo.circuit_id == 0)
    if major > 1 or minor > 10 then
        test("Pinfo.can_desegment-get-1",pinfo.can_desegment == 0)
    end
    test("Pinfo.desegment_len-get-1",pinfo.desegment_len == 0)
    test("Pinfo.desegment_offset-get-1",pinfo.desegment_offset == 0)

    if pinfo.number == 1 then
        test("Pinfo.rel_ts-get-1",pinfo.rel_ts == 0)
        test("Pinfo.delta_ts-get-1",pinfo.delta_ts == 0)
        test("Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0)
    elseif pinfo.number == 2 then
        test("Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.000295)
        test("Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.000295)
        test("Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.000295)
    elseif pinfo.number == 3 then
        test("Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.070031)
        test("Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.069736)
        test("Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.069736)
    elseif pinfo.number == 4 then
        test("Pinfo.rel_ts-get-1",pinfo.rel_ts == 0.070345)
        test("Pinfo.delta_ts-get-1",pinfo.delta_ts == 0.000314)
        test("Pinfo.delta_dis_ts-get-1",pinfo.delta_dis_ts == 0.000314)
    end


    testing(FRAME,"basic setter tests")

    local tmp = pinfo.src
    pinfo.src = pinfo.dst
    pinfo.dst = tmp
    test("Pinfo.src-set-1",tostring(pinfo.src) == dstip)
    test("Pinfo.src-set-1",typeof(pinfo.src) == "Address")
    test("Pinfo.dst-set-1",tostring(pinfo.dst) == srcip)
    test("Pinfo.dst-set-1",typeof(pinfo.dst) == "Address")

    local dl_dst_val = tostring(pinfo.dl_dst)
    local dl_src_val = tostring(pinfo.dl_src)
    tmp = pinfo.dl_src
    pinfo.dl_src = pinfo.dl_dst
    pinfo.dl_dst = tmp
    test("Pinfo.dl_src-set-1",tostring(pinfo.dl_src) == dl_dst_val)
    test("Pinfo.dl_dst-set-1",tostring(pinfo.dl_dst) == dl_src_val)

    tmp = pinfo.net_src
    pinfo.net_src = pinfo.net_dst
    pinfo.net_dst = tmp
    test("Pinfo.net_src-set-1",tostring(pinfo.net_src) == dstip)
    test("Pinfo.net_src-set-1",typeof(pinfo.net_src) == "Address")
    test("Pinfo.net_dst-set-1",tostring(pinfo.net_dst) == srcip)
    test("Pinfo.net_dst-set-1",typeof(pinfo.net_dst) == "Address")

--[[
--there's a bug 9792 causing the pinfo.dst_port setter to actually set src_port
    tmp = pinfo.src_port
    pinfo.src_port = pinfo.dst_port
    pinfo.dst_port = tmp
    test("Pinfo.src_port-set-1",pinfo.src_port == dstport)
    test("Pinfo.dst_port-set-1",pinfo.dst_port == srcport)
--]]
    pinfo.src_port = pinfo.dst_port
    test("Pinfo.src_port-set-1",pinfo.src_port == dstport)

    pinfo.circuit_id = 42
    test("Pinfo.circuit_id-set-1",pinfo.circuit_id == 42)

    if major > 1 or minor > 10 then
        pinfo.can_desegment = 12
        test("Pinfo.can_desegment-set-1",pinfo.can_desegment == 12)
    end
    pinfo.desegment_len = 34
    test("Pinfo.desegment_len-set-1",pinfo.desegment_len == 34)
    pinfo.desegment_offset = 45
    test("Pinfo.desegment_offset-set-1",pinfo.desegment_offset == 45)

    testing(FRAME,"Address functions")
    test("Address-eq-1", pinfo.lo == pinfo.dst)
    test("Address-eq-2", pinfo.lo ~= pinfo.hi)
    test("Address-lt-1", pinfo.lo < pinfo.hi)
    test("Address-lt-2", pinfo.hi > pinfo.lo)
    test("Address-le-1", pinfo.lo <= pinfo.hi)
    test("Address-le-2", pinfo.lo <= pinfo.dst)

    setPassed(FRAME)

end

function tap.draw()
    getResults()
end
