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
local f_frame_proto = Field.new("frame.protocols")
local f_eth_src     = Field.new("eth.src")
local f_eth_dst     = Field.new("eth.dst")
local f_eth_mac     = Field.new("eth.addr")
local f_ip_src      = Field.new("ip.src")
local f_ip_dst      = Field.new("ip.dst")
local f_udp_srcport = Field.new("udp.srcport")
local f_udp_dstport = Field.new("udp.dstport")
local f_bootp_hw    = Field.new("bootp.hw.mac_addr")
local f_bootp_opt   = Field.new("bootp.option.type")

test("Field__tostring-1", tostring(f_frame_proto) == "frame.protocols")

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


    testing("FieldInfo")

    -- check ether addr
    local fi_eth_src = f_eth_src()
    test("FieldInfo.range-0",pcall(getFieldInfo,fi_eth_src,"range"))
    local eth_macs = { f_eth_mac() }
    local eth_src1 = tostring(f_eth_src().range)
    local eth_src2 = tostring(tvb:range(6,6))
    local eth_src3 = tostring(eth_macs[2].tvb)

    test("FieldInfo.range-1", eth_src1 == eth_src2)
    test("FieldInfo.range-2", eth_src1 == eth_src3)
    test("FieldInfo.range-3",not pcall(setFieldInfo,fi_eth_src,"range",3))

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


