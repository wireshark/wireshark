----------------------------------------
-- script-name: pseudoheader.lua
-- Test PseudoHeader objects and writing them with a Dumper.
--
-- The first argument is the name of a pcap file to write.
----------------------------------------

local testlib = require("testlib")

local FIELDS = "fields"
local DUMP = "dump"

testlib.init({ [FIELDS] = 13, [DUMP] = 5 })

local args = { ... }
local filename = args[1]

-- Returns the fields yielded by pairs() as a table.
local function fields(ph)
    local t = {}
    for k, v in pairs(ph) do
        t[k] = v
    end
    return t
end

testlib.testing(FIELDS, "PseudoHeader fields")

local none = PseudoHeader.none()
testlib.test(FIELDS, "none type_name", none.type_name == "none")
testlib.test(FIELDS, "none fields", next(fields(none)) == nil)

local eth = PseudoHeader.eth(4)
testlib.test(FIELDS, "eth type_name", eth.type_name == "eth")
testlib.test(FIELDS, "eth fcs_len", fields(eth).fcs_len == 4)
testlib.test(FIELDS, "eth default fcs_len", fields(PseudoHeader.eth()).fcs_len == -1)

local atm = PseudoHeader.atm(5, 42, 1234, 1, 3, 0, 100)
local f = fields(atm)
testlib.test(FIELDS, "atm type_name", atm.type_name == "atm")
testlib.test(FIELDS, "atm fields", f.aal == 5 and f.vpi == 42 and f.vci == 1234 and
    f.channel == 1 and f.cells == 3 and f.aal5t_u2u == 0 and f.aal5t_len == 100)

local mtp2 = PseudoHeader.mtp2(1, 0, 7)
f = fields(mtp2)
testlib.test(FIELDS, "mtp2 type_name", mtp2.type_name == "mtp2")
testlib.test(FIELDS, "mtp2 fields", f.sent == 1 and f.annex_a_used == 0 and f.link_number == 7)

testlib.test(FIELDS, "tostring", tostring(atm) == "PseudoHeader: type=atm")

-- PseudoHeaders are stored in their userdata, so they need no finalizer.
testlib.test(FIELDS, "no __gc", debug.getmetatable(atm).__gc == nil)

-- Many PseudoHeaders can be created and collected, and the others are
-- not affected.
for i = 1, 10000 do
    local ph = PseudoHeader.atm(5, i % 256, i)
end
collectgarbage()
collectgarbage()
f = fields(atm)
testlib.test(FIELDS, "atm after collection", f.vpi == 42 and f.vci == 1234)
testlib.test(FIELDS, "eth after collection", fields(eth).fcs_len == 4)

testlib.testing(DUMP, "Dumper with PseudoHeader")

-- The pcap SunATM link type writes the VPI and VCI from the ATM
-- pseudoheader before the packet data.
local d = Dumper.new(filename, wtap_name_to_file_type_subtype("pcap"), wtap_encaps.ATM_PDUS)
local payload = ByteArray.new("aa bb cc dd")
d:dump(1.5, atm, payload)
d:close()

local fh = io.open(filename, "rb")
local data = fh:read("a")
fh:close()

-- pcap file header (24 bytes), record header (16 bytes), SunATM header
-- (4 bytes), then the packet data.
testlib.test(DUMP, "file length", #data == 24 + 16 + 4 + payload:len())
local caplen = string.unpack("=I4", data, 24 + 8 + 1)
testlib.test(DUMP, "caplen", caplen == 4 + payload:len())
testlib.test(DUMP, "vpi", string.byte(data, 24 + 16 + 2) == 42)
testlib.test(DUMP, "vci", string.unpack(">I2", data, 24 + 16 + 3) == 1234)
testlib.test(DUMP, "payload", string.sub(data, 24 + 16 + 5) == payload:raw())

testlib.getResults()
