-- test script for various Lua functions
-- use with dhcp.pcap in test/captures directory


------------- general test helper funcs ------------
local FRAME = "frame"
local ETH = "eth"
local IP = "ip"
local BOOTP = "bootp"
local OTHER = "other"
local PDISS = "postdissector"

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
local taptests = { [FRAME]=4, [ETH]=4, [IP]=3, [BOOTP]=2, [OTHER]=16 }
local function getResults()
    print("\n-----------------------------\n")
    for k,v in pairs(taptests) do
        if passed[k] ~= v then
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

local pkt_fields = { [FRAME] = {}, [PDISS] = {} }
local function getAllFieldInfos(type)
    local fields = { all_field_infos() }
    local fieldnames = {}
    for i,v in ipairs(fields) do
        fieldnames[i] = v.name
    end
    local pktnum = getPktCount(type)
    pkt_fields[type][pktnum] = { ["num"] = #fields, ["fields"] = fieldnames }
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
testing(OTHER,"negative tests")
local orig_test = test
test = function (...)
    if orig_test(OTHER,...) then
        setPassed(OTHER)
    end
end
test("Listener.new-1",not pcall(makeListener,"FooBARhowdy"))
test("Listener.new-2",not pcall(makeListener,"ip","FooBARhowdy"))
local tmptap = Listener.new()
local func = function(...)
    passed[OTHER] = 0
    error("This shouldn't be called!")
end
test("Listener.set-3",pcall(setListener,tmptap,"packet",func))
test("Listener.set-4",pcall(setListener,tmptap,"reset",func))
test("Listener.set-5",pcall(setListener,tmptap,"draw",func))
test("Listener.set-6",not pcall(setListener,Listener,"packet",func))
test("Listener.set-7",not pcall(setListener,Listener,"reset",func))
test("Listener.set-8",not pcall(setListener,Listener,"draw",func))
test("Listener.set-9",not pcall(setListener,Listener,"foobar",func))

test("Listener.get-10",not pcall(getListener,tmptap,"packet",func))
test("Listener.get-11",not pcall(getListener,tmptap,"reset",func))
test("Listener.get-12",not pcall(getListener,tmptap,"draw",func))

print("removing tmptap twice")
test("Listener.remove-13",pcall(tmptap.remove,tmptap))
test("Listener.remove-14",pcall(tmptap.remove,tmptap))

test("typeof-15", typeof(tmptap) == "Listener")

-- revert to original test function
test = orig_test


-- declare some field extractors
local f_eth_src     = Field.new("eth.src")
local f_eth_dst     = Field.new("eth.dst")
local f_eth_mac     = Field.new("eth.addr")
local f_ip_src      = Field.new("ip.src")
local f_ip_dst      = Field.new("ip.dst")
local f_bootp_hw    = Field.new("bootp.hw.mac_addr")
local f_bootp_opt   = Field.new("bootp.option.type")

local tap_frame = Listener.new(nil,nil,true)
local tap_eth = Listener.new("eth")
local tap_ip = Listener.new("ip","bootp")
local tap_bootp = Listener.new("bootp","bootp.option.dhcp == 1")

local second_time = false

function tap_frame.packet(pinfo,tvb,frame)
    incPktCount(FRAME)
    testing(FRAME,"Frame")

    test(FRAME,"arg-1", typeof(pinfo) == "Pinfo")
    test(FRAME,"arg-2", typeof(tvb) == "Tvb")
    test(FRAME,"arg-3", frame == nil)

    test(FRAME,"pinfo.number-1",pinfo.number == getPktCount(FRAME))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    test(FRAME,"FieldInfo.range-1", eth_src1 == eth_src2)

    getAllFieldInfos(FRAME)

    setPassed(FRAME)
end

function tap_eth.packet(pinfo,tvb,eth)
    incPktCount(ETH)

    -- on the 4th run of eth, remove the ip one and add a new bootp one
    if getPktCount(ETH) == 4 then
        testing(ETH,"removing ip tap, replacing bootp tap")
        tap_ip:remove()
        tap_bootp:remove()
        tap_bootp = Listener.new("bootp")
        tap_bootp.packet = bootp_packet
        second_time = true
    end

    testing(ETH,"Eth")

    test(ETH,"arg-1", typeof(pinfo) == "Pinfo")
    test(ETH,"arg-2", typeof(tvb) == "Tvb")
    test(ETH,"arg-3", type(eth) == "table")

    test(ETH,"pinfo.number-1",pinfo.number == getPktCount(ETH))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    test(ETH,"FieldInfo.range-1", eth_src1 == eth_src2)

    setPassed(ETH)
end

function tap_ip.packet(pinfo,tvb,ip)
    incPktCount(IP)
    testing(IP,"IP")

    test(IP,"arg-1", typeof(pinfo) == "Pinfo")
    test(IP,"arg-2", typeof(tvb) == "Tvb")
    test(IP,"arg-3", type(ip) == "table")

    test(IP,"pinfo.number-1",pinfo.number == getPktCount(IP))

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    test(IP,"FieldInfo.range-1", eth_src1 == eth_src2)

    setPassed(IP)
end

bootp_packet = function (pinfo,tvb,bootp)
    incPktCount(BOOTP)
    testing(BOOTP,"Bootp")

    test(BOOTP,"arg-1", typeof(pinfo) == "Pinfo")
    test(BOOTP,"arg-2", typeof(tvb) == "Tvb")
    test(BOOTP,"arg-3", bootp == nil)

    if not second_time then
        test(BOOTP,"pinfo.number-1",pinfo.number == getPktCount(BOOTP))
    else
        test(BOOTP,"pinfo.number-1",pinfo.number == 4)
    end

    -- check ether addr
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    test(BOOTP,"FieldInfo.range-1", eth_src1 == eth_src2)

    setPassed(BOOTP)
end
tap_bootp.packet = bootp_packet

function tap_frame.reset()
    -- reset never gets called in tshark (sadly)
    if not GUI_ENABLED then
        error("reset called!!")
    end
end

function tap_frame.draw()
    test(OTHER,"all_field_infos", checkAllFieldInfos())
    setPassed(OTHER)
    getResults()
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
    incPktCount(PDISS)
    getAllFieldInfos(PDISS)
end


