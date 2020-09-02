-- test script for wslua Field/FieldInfo functions
-- use with dhcp.pcap in test/captures directory


------------- helper funcs ------------
local packet_count = 0
local function incPktCount(name)
    packet_count = packet_count + 1
end

local function testing(...)
    print("---- Testing "..tostring(...).." for packet #"..packet_count.." ----")
end

local function test(name, ...)
    io.stdout:write("test "..name.."-"..packet_count.."...")
    if (...) == true then
        io.stdout:write("passed\n")
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

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

testing("Field")


test("Field.new-0",pcall(makeField,"ip.src"))
test("Field.new-1",not pcall(makeField,"FooBARhowdy"))
test("Field.new-2",not pcall(makeField))
test("Field.new-3",not pcall(makeField,""))
test("Field.new-4",not pcall(makeField,"IP.SRC"))

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

test("Field__tostring-1", tostring(f_frame_proto) == "frame.protocols")

test("Field.name-1", f_frame_proto.name == "frame.protocols")
test("Field.name-2", f_eth_src.name == "eth.src")

test("Field.display-1", f_frame_proto.display == "Protocols in frame")
test("Field.display-2", f_eth_src.display == "Source")

test("Field.type-1", f_frame_proto.type == ftypes.STRING)
test("Field.type-2", f_eth_src.type == ftypes.ETHER)
test("Field.type-3", f_ip_src.type == ftypes.IPv4)
test("Field.type-4", f_udp_srcport.type == ftypes.UINT16)
test("Field.type-5", f_dhcp_opt.type == ftypes.UINT8)

-- make sure can't create a FieldInfo outside tap
test("Field__call-1",not pcall(makeFieldInfo,f_eth_src))

local tap = Listener.new()

--------------------------

function tap.packet(pinfo,tvb)
    incPktCount()

    testing("Field")
    test("Field__tostring-2", tostring(f_frame_proto) == "frame.protocols")

    -- make sure can't create a Field inside tap
    test("Field.new-5",not pcall(makeField,"ip.src"))

    test("Field__call-2",pcall(makeFieldInfo,f_eth_src))

    test("Field.name-3", f_frame_proto.name == "frame.protocols")
    test("Field.name-4", f_eth_src.name == "eth.src")

    test("Field.display-3", f_frame_proto.display == "Protocols in frame")
    test("Field.display-4", f_eth_src.display == "Source")

    test("Field.type-6", f_frame_proto.type == ftypes.STRING)
    test("Field.type-7", f_eth_src.type == ftypes.ETHER)
    test("Field.type-8", f_ip_src.type == ftypes.IPv4)
    test("Field.type-9", f_udp_srcport.type == ftypes.UINT16)
    test("Field.type-10", f_dhcp_opt.type == ftypes.UINT8)

    testing("FieldInfo")

    local finfo_udp_srcport = f_udp_srcport()
    test("FieldInfo.name-1", finfo_udp_srcport.name == "udp.srcport")
    test("FieldInfo.type-1", finfo_udp_srcport.type == ftypes.UINT16)
    test("FieldInfo.little_endian-1", finfo_udp_srcport.little_endian == false)
    -- the following should be true, but UDP doesn't set it right?
    -- test("FieldInfo.big_endian-1", finfo_udp_srcport.big_endian == true)
    test("FieldInfo.is_url-1", finfo_udp_srcport.is_url == false)
    test("FieldInfo.offset-1", finfo_udp_srcport.offset == 34)
    test("FieldInfo.source-1", finfo_udp_srcport.source == tvb)

    -- check ether addr
    local fi_eth_src = f_eth_src()
    test("FieldInfo.type-2", fi_eth_src.type == ftypes.ETHER)
    test("FieldInfo.range-0",pcall(getFieldInfo,fi_eth_src,"range"))
    local eth_macs = { f_eth_mac() }
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    local eth_src3 = tostring(eth_macs[2].tvb)

    test("FieldInfo.range-1", eth_src1 == eth_src2)
    test("FieldInfo.range-2", eth_src1 == eth_src3)
    test("FieldInfo.range-3",not pcall(setFieldInfo,fi_eth_src,"range",3))
    test("FieldInfo.range-4", tostring(f_frame_encap_type().range) == "<EMPTY>")

    test("FieldInfo.generated-1", f_frame_proto().generated == true)
    test("FieldInfo.generated-2", eth_macs[2].generated == false)
    test("FieldInfo.generated-3",not pcall(setFieldInfo,fi_eth_src,"generated",3))

    test("FieldInfo.name-1", fi_eth_src.name == "eth.src")
    test("FieldInfo.name-2",not pcall(setFieldInfo,fi_eth_src,"name","3"))

    test("FieldInfo.label-1", fi_eth_src.label == tostring(fi_eth_src))
    test("FieldInfo.label-2", fi_eth_src.label == toMacAddr(eth_src1))
    test("FieldInfo.label-3",not pcall(setFieldInfo,fi_eth_src,"label","3"))

    test("FieldInfo.display-1", select(1, string.find(fi_eth_src.display, toMacAddr(eth_src1))) ~= nil)
    test("FieldInfo.display-2",not pcall(setFieldInfo,fi_eth_src,"display","3"))

    test("FieldInfo.eq-1", eth_macs[2] == select(2, f_eth_mac()))
    test("FieldInfo.eq-2", eth_macs[1] ~= fi_eth_src)
    test("FieldInfo.eq-3", eth_macs[1] == f_eth_dst())

    test("FieldInfo.offset-1", eth_macs[1].offset == 0)
    test("FieldInfo.offset-2", -fi_eth_src == 6)
    test("FieldInfo.offset-3",not pcall(setFieldInfo,fi_eth_src,"offset","3"))

    test("FieldInfo.len-1", fi_eth_src.len == 6)
    test("FieldInfo.len-2",not pcall(setFieldInfo,fi_eth_src,"len",6))

    if packet_count == 4 then
        print("\n-----------------------------\n")
        print("All tests passed!\n\n")
    end

end


