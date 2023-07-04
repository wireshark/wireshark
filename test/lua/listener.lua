-- test script for various Lua functions
-- use with dhcp.pcap in test/captures directory

local testlib = require("testlib")

------------- general test helper funcs ------------
local FRAME = "frame"
local ETH = "eth"
local IP = "ip"
local DHCP = "dhcp"
local OTHER = "other"
local PDISS = "postdissector"

-- expected number of runs per type
-- note ip (5 tests) only runs 3 times because it gets removed
-- and dhcp (5 tests) only runs twice because the filter makes it run
-- once and then it gets replaced with a different one for the second time
local n_frames = 4
local taptests = {
        [FRAME]=5*n_frames,
        [ETH]=5*n_frames,
        [IP]=5*3,
        [DHCP]=5*2,
        [OTHER]=16,
        [PDISS]=n_frames,
}
testlib.init(taptests)

local pkt_fields = { [FRAME] = {}, [PDISS] = {} }
local function getAllFieldInfos(group)
    local fields = { all_field_infos() }
    local fieldnames = {}
    for i,v in ipairs(fields) do
        fieldnames[i] = v.name
    end
    local pktnum = testlib.getPktCount(group)
    pkt_fields[group][pktnum] = { ["num"] = #fields, ["fields"] = fieldnames }
end

local function dumpAllFieldInfos()
    for i,v in ipairs(pkt_fields[FRAME]) do
        print("In frame tap for packet ".. i ..":")
        print("    number of fields = ".. v.num)
        for _,name in ipairs(v.fields) do
            print("    field = ".. name)
        end
        local w = pkt_fields[PDISS][i]
        print("In postdissector for packet ".. i ..":")
        print("    number of fields = ".. w.num)
        for _,name in ipairs(w.fields) do
            print("    field = ".. name)
        end
    end
end

local function checkAllFieldInfos()
    for i,v in ipairs(pkt_fields[FRAME]) do
        local numfields = v.num
        if numfields ~= pkt_fields[PDISS][i].num then
            print("Tap and postdissector do not have same number of fields!")
            return false
        end
        if numfields < 100 then
            print("Too few fields!")
            return false
        end
    end
    return true
end


---------
-- the following are so we can use pcall (which needs a function to call)
local function makeListener(...)
    local foo = Listener.new(...)
end

local function setListener(tap,name,value)
    tap[name] = value
end

local function getListener(tap,name)
    local foo = tap[name]
end

------------- test script ------------
testlib.testing(OTHER,"negative tests")
testlib.test(OTHER,"Listener.new-1",not pcall(makeListener,"FooBARhowdy"))
testlib.test(OTHER,"Listener.new-2",not pcall(makeListener,"ip","FooBARhowdy"))
local tmptap = Listener.new()
local func = function(...)
    passed[OTHER] = 0
    error("This shouldn't be called!")
end
testlib.test(OTHER,"Listener.set-3",pcall(setListener,tmptap,"packet",func))
testlib.test(OTHER,"Listener.set-4",pcall(setListener,tmptap,"reset",func))
testlib.test(OTHER,"Listener.set-5",pcall(setListener,tmptap,"draw",func))
testlib.test(OTHER,"Listener.set-6",not pcall(setListener,Listener,"packet",func))
testlib.test(OTHER,"Listener.set-7",not pcall(setListener,Listener,"reset",func))
testlib.test(OTHER,"Listener.set-8",not pcall(setListener,Listener,"draw",func))
testlib.test(OTHER,"Listener.set-9",not pcall(setListener,Listener,"foobar",func))

testlib.test(OTHER,"Listener.get-10",not pcall(getListener,tmptap,"packet",func))
testlib.test(OTHER,"Listener.get-11",not pcall(getListener,tmptap,"reset",func))
testlib.test(OTHER,"Listener.get-12",not pcall(getListener,tmptap,"draw",func))

print("removing tmptap twice")
testlib.test(OTHER,"Listener.remove-13",pcall(tmptap.remove,tmptap))
testlib.test(OTHER,"Listener.remove-14",pcall(tmptap.remove,tmptap))

testlib.test(OTHER,"typeof-15", typeof(tmptap) == "Listener")


-- declare some field extractors
local f_eth_src     = Field.new("eth.src")
local f_eth_dst     = Field.new("eth.dst")
local f_eth_mac     = Field.new("eth.addr")
local f_ip_src      = Field.new("ip.src")
local f_ip_dst      = Field.new("ip.dst")
local f_dhcp_hw    = Field.new("dhcp.hw.mac_addr")
local f_dhcp_opt   = Field.new("dhcp.option.type")

local tap_frame = Listener.new(nil,nil,true)
local tap_eth = Listener.new("eth")
local tap_ip = Listener.new("ip","dhcp")
local tap_dhcp = Listener.new("dhcp","dhcp.option.dhcp == 1")

local second_time = false

function tap_frame.packet(pinfo,tvb,frame)
    testlib.countPacket(FRAME)
    testlib.testing(FRAME,"Frame")

    testlib.test(FRAME,"arg-1", typeof(pinfo) == "Pinfo")
    testlib.test(FRAME,"arg-2", typeof(tvb) == "Tvb")
    testlib.test(FRAME,"arg-3", frame == nil)

    testlib.test(FRAME,"pinfo.number-1",pinfo.number == testlib.getPktCount(FRAME))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    testlib.test(FRAME,"FieldInfo.range-1", eth_src1 == eth_src2)

    getAllFieldInfos(FRAME)
end

function tap_eth.packet(pinfo,tvb,eth)
    testlib.countPacket(ETH)

    -- on the 4th run of eth, remove the ip one and add a new dhcp one
    if testlib.getPktCount(ETH) == 4 then
        testlib.testing(ETH,"removing ip tap, replacing dhcp tap")
        tap_ip:remove()
        tap_dhcp:remove()
        tap_dhcp = Listener.new("dhcp")
        tap_dhcp.packet = dhcp_packet
        second_time = true
    end

    testlib.testing(ETH,"Eth")

    testlib.test(ETH,"arg-1", typeof(pinfo) == "Pinfo")
    testlib.test(ETH,"arg-2", typeof(tvb) == "Tvb")
    testlib.test(ETH,"arg-3", type(eth) == "table")

    testlib.test(ETH,"pinfo.number-1",pinfo.number == testlib.getPktCount(ETH))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    testlib.test(ETH,"FieldInfo.range-1", eth_src1 == eth_src2)
end

function tap_ip.packet(pinfo,tvb,ip)
    testlib.countPacket(IP)
    testlib.testing(IP,"IP")

    testlib.test(IP,"arg-1", typeof(pinfo) == "Pinfo")
    testlib.test(IP,"arg-2", typeof(tvb) == "Tvb")
    testlib.test(IP,"arg-3", type(ip) == "table")

    testlib.test(IP,"pinfo.number-1",pinfo.number == testlib.getPktCount(IP))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    testlib.test(IP,"FieldInfo.range-1", eth_src1 == eth_src2)
end

dhcp_packet = function (pinfo,tvb,dhcp)
    testlib.countPacket(DHCP)
    testlib.testing(DHCP,"DHCP")

    testlib.test(DHCP,"arg-1", typeof(pinfo) == "Pinfo")
    testlib.test(DHCP,"arg-2", typeof(tvb) == "Tvb")
    testlib.test(DHCP,"arg-3", dhcp == nil)

    if not second_time then
        testlib.test(DHCP,"pinfo.number-1",pinfo.number == testlib.getPktCount(DHCP))
    else
        testlib.test(DHCP,"pinfo.number-1",pinfo.number == 4)
    end

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    testlib.test(DHCP,"FieldInfo.range-1", eth_src1 == eth_src2)
end
tap_dhcp.packet = dhcp_packet

function tap_frame.reset()
    -- reset never gets called in tshark (sadly)
    --[[ XXX: this is no longer the case?!
    if not GUI_ENABLED then
        error("reset called!!")
    end
    --]]
end

function tap_frame.draw()
    testlib.test(OTHER,"all_field_infos", checkAllFieldInfos())
    testlib.getResults()
end

-- max_gap.lua
-- create a gap.max field containing the maximum gap between two packets between two ip nodes

-- we create a "protocol" for our tree
local max_gap_p = Proto("gap","Gap in IP conversations")

-- we create our fields
local max_gap_field = ProtoField.float("gap.max")

-- we add our fields to the protocol
max_gap_p.fields = { max_gap_field }

-- then we register max_gap_p as a postdissector
register_postdissector(max_gap_p,true)
function max_gap_p.dissector(tvb,pinfo,tree)
    testlib.countPacket(PDISS)
    getAllFieldInfos(PDISS)
    testlib.pass(PDISS)
end


