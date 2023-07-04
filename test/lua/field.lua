-- test script for wslua Field/FieldInfo functions
-- use with dhcp.pcap in test/captures directory
local testlib = require("testlib")

local FRAME = "frame"
local PER_FRAME = "per-frame"
local OTHER = "other"

local n_frames = 1
testlib.init({
    [FRAME] = n_frames,
    [PER_FRAME] = n_frames*43,
    [OTHER] = 16,
})

------------- helper funcs ------------

local function toMacAddr(addrhex)
    return addrhex:gsub("..","%0:"):sub(1,-2)
end

-- the following are so we can use pcall (which needs a function to call)
local function makeField(name)
    local foo = Field.new(name)
    return true
end

local function makeFieldInfo(field)
    local foo = field()
    return true
end

local function setFieldInfo(finfo,name,value)
    finfo[name] = value
    return true
end

local function getFieldInfo(finfo,name)
    local foo = finfo[name]
    return true
end

--------------------------

testlib.testing(OTHER, "Field")

testlib.test(OTHER,"Field.new-0",pcall(makeField,"ip.src"))
testlib.test(OTHER,"Field.new-1",not pcall(makeField,"FooBARhowdy"))
testlib.test(OTHER,"Field.new-2",not pcall(makeField))
testlib.test(OTHER,"Field.new-3",not pcall(makeField,""))
testlib.test(OTHER,"Field.new-4",not pcall(makeField,"IP.SRC"))

-- declare some field extractors
local f_frame_encap_type = Field.new("frame.encap_type")
local f_frame_proto = Field.new("frame.protocols")
local f_eth_src     = Field.new("eth.src")
local f_eth_dst     = Field.new("eth.dst")
local f_eth_mac     = Field.new("eth.addr")
local f_ip_src      = Field.new("ip.src")
local f_ip_dst      = Field.new("ip.dst")
local f_udp_srcport = Field.new("udp.srcport")
local f_udp_dstport = Field.new("udp.dstport")
local f_dhcp_hw    = Field.new("dhcp.hw.mac_addr")
local f_dhcp_opt   = Field.new("dhcp.option.type")

testlib.test(OTHER,"Field__tostring-1", tostring(f_frame_proto) == "frame.protocols")

testlib.test(OTHER,"Field.name-1", f_frame_proto.name == "frame.protocols")
testlib.test(OTHER,"Field.name-2", f_eth_src.name == "eth.src")

testlib.test(OTHER,"Field.display-1", f_frame_proto.display == "Protocols in frame")
testlib.test(OTHER,"Field.display-2", f_eth_src.display == "Source")

testlib.test(OTHER,"Field.type-1", f_frame_proto.type == ftypes.STRING)
testlib.test(OTHER,"Field.type-2", f_eth_src.type == ftypes.ETHER)
testlib.test(OTHER,"Field.type-3", f_ip_src.type == ftypes.IPv4)
testlib.test(OTHER,"Field.type-4", f_udp_srcport.type == ftypes.UINT16)
testlib.test(OTHER,"Field.type-5", f_dhcp_opt.type == ftypes.UINT8)

-- make sure can't create a FieldInfo outside tap
testlib.test(OTHER,"Field__call-1",not pcall(makeFieldInfo,f_eth_src))

local tap = Listener.new()

--------------------------

function tap.packet(pinfo,tvb)
    testlib.countPacket(FRAME)

    testlib.testing(FRAME,"Field")
    testlib.test(PER_FRAME,"Field__tostring-2", tostring(f_frame_proto) == "frame.protocols")

    -- make sure can't create a Field inside tap
    testlib.test(PER_FRAME,"Field.new-5",not pcall(makeField,"ip.src"))

    testlib.test(PER_FRAME,"Field__call-2",pcall(makeFieldInfo,f_eth_src))

    testlib.test(PER_FRAME,"Field.name-3", f_frame_proto.name == "frame.protocols")
    testlib.test(PER_FRAME,"Field.name-4", f_eth_src.name == "eth.src")

    testlib.test(PER_FRAME,"Field.display-3", f_frame_proto.display == "Protocols in frame")
    testlib.test(PER_FRAME,"Field.display-4", f_eth_src.display == "Source")

    testlib.test(PER_FRAME,"Field.type-6", f_frame_proto.type == ftypes.STRING)
    testlib.test(PER_FRAME,"Field.type-7", f_eth_src.type == ftypes.ETHER)
    testlib.test(PER_FRAME,"Field.type-8", f_ip_src.type == ftypes.IPv4)
    testlib.test(PER_FRAME,"Field.type-9", f_udp_srcport.type == ftypes.UINT16)
    testlib.test(PER_FRAME,"Field.type-10", f_dhcp_opt.type == ftypes.UINT8)

    testlib.testing(FRAME,"FieldInfo")

    local finfo_udp_srcport = f_udp_srcport()
    testlib.test(PER_FRAME,"FieldInfo.name-1", finfo_udp_srcport.name == "udp.srcport")
    testlib.test(PER_FRAME,"FieldInfo.type-1", finfo_udp_srcport.type == ftypes.UINT16)
    testlib.test(PER_FRAME,"FieldInfo.little_endian-1", finfo_udp_srcport.little_endian == false)
    testlib.test(PER_FRAME,"FieldInfo.big_endian-1", finfo_udp_srcport.big_endian == true)
    testlib.test(PER_FRAME,"FieldInfo.is_url-1", finfo_udp_srcport.is_url == false)
    testlib.test(PER_FRAME,"FieldInfo.offset-1", finfo_udp_srcport.offset == 34)
    testlib.test(PER_FRAME,"FieldInfo.source-1", finfo_udp_srcport.source == tvb)

    -- check ether addr
    local fi_eth_src = f_eth_src()
    testlib.test(PER_FRAME,"FieldInfo.type-2", fi_eth_src.type == ftypes.ETHER)
    testlib.test(PER_FRAME,"FieldInfo.range-0",pcall(getFieldInfo,fi_eth_src,"range"))
    local eth_macs = { f_eth_mac() }
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    local eth_src3 = tostring(eth_macs[2].tvb)

    testlib.test(PER_FRAME,"FieldInfo.range-1", eth_src1 == eth_src2)
    testlib.test(PER_FRAME,"FieldInfo.range-2", eth_src1 == eth_src3)
    testlib.test(PER_FRAME,"FieldInfo.range-3",not pcall(setFieldInfo,fi_eth_src,"range",3))
    testlib.test(PER_FRAME,"FieldInfo.range-4", tostring(f_frame_encap_type().range) == "<EMPTY>")

    testlib.test(PER_FRAME,"FieldInfo.generated-1", f_frame_proto().generated == true)
    testlib.test(PER_FRAME,"FieldInfo.generated-2", eth_macs[2].generated == false)
    testlib.test(PER_FRAME,"FieldInfo.generated-3",not pcall(setFieldInfo,fi_eth_src,"generated",3))

    testlib.test(PER_FRAME,"FieldInfo.name-1", fi_eth_src.name == "eth.src")
    testlib.test(PER_FRAME,"FieldInfo.name-2",not pcall(setFieldInfo,fi_eth_src,"name","3"))

    testlib.test(PER_FRAME,"FieldInfo.label-1", fi_eth_src.label == tostring(fi_eth_src))
    testlib.test(PER_FRAME,"FieldInfo.label-2", fi_eth_src.label == toMacAddr(eth_src1))
    testlib.test(PER_FRAME,"FieldInfo.label-3",not pcall(setFieldInfo,fi_eth_src,"label","3"))

    testlib.test(PER_FRAME,"FieldInfo.display-1", select(1, string.find(fi_eth_src.display, toMacAddr(eth_src1))) ~= nil)
    testlib.test(PER_FRAME,"FieldInfo.display-2",not pcall(setFieldInfo,fi_eth_src,"display","3"))

    testlib.test(PER_FRAME,"FieldInfo.eq-1", eth_macs[2] == select(2, f_eth_mac()))
    testlib.test(PER_FRAME,"FieldInfo.eq-2", eth_macs[1] ~= fi_eth_src)
    testlib.test(PER_FRAME,"FieldInfo.eq-3", eth_macs[1] == f_eth_dst())

    testlib.test(PER_FRAME,"FieldInfo.offset-1", eth_macs[1].offset == 0)
    testlib.test(PER_FRAME,"FieldInfo.offset-2", -fi_eth_src == 6)
    testlib.test(PER_FRAME,"FieldInfo.offset-3",not pcall(setFieldInfo,fi_eth_src,"offset","3"))

    testlib.test(PER_FRAME,"FieldInfo.len-1", fi_eth_src.len == 6)
    testlib.test(PER_FRAME,"FieldInfo.len-2",not pcall(setFieldInfo,fi_eth_src,"len",6))

    testlib.pass(FRAME)
end

function tap.draw()
    testlib.getResults()
end
