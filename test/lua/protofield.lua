----------------------------------------
-- script-name: protofield.lua
-- test the ProtoField API
----------------------------------------

local testlib = require("testlib")

local FRAME = "frame"
local PER_FRAME = "per-frame"
local OTHER = "other"

-- expected number of runs
local n_frames = 4
local taptests = {
    [FRAME]=n_frames,
    [PER_FRAME]=n_frames*8,
    [OTHER]=57,
}
testlib.init(taptests)

------------- test script ------------

----------------------------------------
local test_proto = Proto.new("test", "Test Proto")
test_proto.fields.time_field = ProtoField.uint16("test.time", "Time", base.UNIT_STRING, {" sec", " secs"})
test_proto.fields.dist_field = ProtoField.uint16("test.dist", "Distance", base.UNIT_STRING, {" km"})
test_proto.fields.filtered_field = ProtoField.uint16("test.filtered", "Filtered Field", base.DEC)

-- Field type: CHAR
success = pcall(ProtoField.new, "char", "test.char0", ftypes.CHAR)
testlib.test(OTHER,"ProtoField-char", success)

success = pcall(ProtoField.new, "char base NONE without valuestring", "test.char1", ftypes.CHAR, nil, base.NONE)
testlib.test(OTHER,"ProtoField-char-without-valuestring", not success)

success = pcall(ProtoField.new, "char base NONE with valuestring", "test.char2", ftypes.CHAR, {1, "Value"}, base.NONE)
testlib.test(OTHER,"ProtoField-char-with-valuestring", success)

success = pcall(ProtoField.new, "char base DEC", "test.char3", ftypes.CHAR, nil, base.DEC)
testlib.test(OTHER,"ProtoField-char-base-dec", not success)

success = pcall(ProtoField.new, "char base UNIT_STRING", "test.char4", ftypes.CHAR, {" m"}, base.UNIT_STRING)
testlib.test(OTHER,"ProtoField-char-unit-string", not success)

success = pcall(ProtoField.new, "char base RANGE_STRING", "test.char5", ftypes.CHAR, {{1, 2, "Value"}}, base.RANGE_STRING)
testlib.test(OTHER,"ProtoField-char-range-string", success)

success = pcall(ProtoField.new, "char base RANGE_STRING and SPECIAL_VALS", "test.char6", ftypes.CHAR, {{1, 2, "Value"}}, base.RANGE_STRING | base.SPECIAL_VALS)
testlib.test(OTHER,"ProtoField-char-range-string-special-vals", success)

-- Field type: BOOLEAN/UINT64 with (64 bit) mask
success = pcall(ProtoField.new, "boolean", "test.boolean0", ftypes.BOOLEAN, nil, base.HEX, 0x1)
testlib.test(OTHER,"ProtoField-new-bool-mask-trivial", success)

success = pcall(ProtoField.new, "boolean", "test.boolean1", ftypes.BOOLEAN, nil, base.HEX, "1")
testlib.test(OTHER,"ProtoField-new-bool-mask-string", success)

success = pcall(ProtoField.new, "boolean", "test.boolean2", ftypes.BOOLEAN, nil, base.HEX, UInt64(0x00000001, 0x0))
testlib.test(OTHER,"ProtoField-new-bool-mask-uint64", success)

success = pcall(ProtoField.new, "boolean", "test.boolean3", ftypes.BOOLEAN, nil, base.NONE, "invalid") -- 0
testlib.test(OTHER,"ProtoField-new-bool-mask-string-invalid", success)

success = pcall(ProtoField.new, "boolean", "test.boolean4", ftypes.BOOLEAN, nil, base.HEX, "-1") -- 0xFFFFFFFFFFFFFFFF
testlib.test(OTHER,"ProtoField-new-bool-mask-negative", success)

success = pcall(ProtoField.new, "boolean", "test.boolean5", ftypes.BOOLEAN, nil, base.NONE)
testlib.test(OTHER,"ProtoField-new-bool-mask-none", success)

success = pcall(ProtoField.new, "boolean", "test.boolean6", ftypes.BOOLEAN, nil, base.NONE, nil)
testlib.test(OTHER,"ProtoField-new-bool-mask-nil", success)

success = pcall(ProtoField.new, "boolean", "test.boolean7", ftypes.BOOLEAN, nil, base.HEX, "0x00FFFFFF00000000")
testlib.test(OTHER,"ProtoField-new-bool-mask-hex", success)

success = pcall(ProtoField.bool, "test.boolean10", nil, 64, nil, 0x1)
testlib.test(OTHER,"ProtoField-bool-mask-trivial", success)

success = pcall(ProtoField.bool, "test.boolean11", nil, 64, nil, "1")
testlib.test(OTHER,"ProtoField-bool-mask-string", success)

success = pcall(ProtoField.bool, "test.boolean12", nil, 64, nil, UInt64(0x00000001, 0x0))
testlib.test(OTHER,"ProtoField-bool-mask-uint64", success)

success = pcall(ProtoField.bool, "test.boolean13", nil, base.NONE, nil, "invalid") -- 0
testlib.test(OTHER,"ProtoField-bool-mask-string-invalid", success)

success = pcall(ProtoField.bool, "test.boolean14", nil, 64, nil, "-1") -- 0xFFFFFFFFFFFFFFFF
testlib.test(OTHER,"ProtoField-bool-mask-negative", success)

success = pcall(ProtoField.bool, "test.boolean15", nil, base.NONE, nil)
testlib.test(OTHER,"ProtoField-bool-mask-none", success)

success = pcall(ProtoField.bool, "test.boolean16", nil, base.NONE, nil, nil)
testlib.test(OTHER,"ProtoField-bool-mask-nil", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_0", ftypes.UINT64, nil, base.HEX, 0x1)
testlib.test(OTHER,"ProtoField-new-uint64-mask-trivial", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_1", ftypes.UINT64, nil, base.HEX, "1")
testlib.test(OTHER,"ProtoField-new-uint64-mask-string", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_2", ftypes.UINT64, nil, base.HEX, UInt64(0x00000001, 0x0))
testlib.test(OTHER,"ProtoField-new-uint64-mask-uint64", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_3", ftypes.UINT64, nil, base.NONE, "invalid") -- 0
testlib.test(OTHER,"ProtoField-new-uint64-mask-string-invalid", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_4", ftypes.UINT64, nil, base.HEX, "-1") -- 0xFFFFFFFFFFFFFFFF
testlib.test(OTHER,"ProtoField-new-uint64-mask-negative", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_5", ftypes.UINT64, nil, base.NONE)
testlib.test(OTHER,"ProtoField-new-uint64-mask-none", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_6", ftypes.UINT64, nil, base.NONE, nil)
testlib.test(OTHER,"ProtoField-new-uint64-mask-nil", success)

success = pcall(ProtoField.new, "uint64", "test.uint64_7", ftypes.UINT64, nil, base.HEX, "0x00FFFFFF00000000")
testlib.test(OTHER,"ProtoField-new-uint64-mask-hex", success)

success = pcall(ProtoField.uint64, "test.uint64_10", nil, base.HEX, nil, 0x1)
testlib.test(OTHER,"ProtoField-uint64-mask-trivial", success)

success = pcall(ProtoField.uint64, "test.uint64_11", nil, base.HEX, nil, "1")
testlib.test(OTHER,"ProtoField-uint64-mask-string", success)

success = pcall(ProtoField.uint64, "test.uint64_12", nil, base.HEX, nil, UInt64(0x00000001, 0x0))
testlib.test(OTHER,"ProtoField-uint64-mask-uint64", success)

success = pcall(ProtoField.uint64, "test.uint64_13", nil, base.DEC, nil, "invalid") -- 0
testlib.test(OTHER,"ProtoField-uint64-mask-string-invalid", success)

success = pcall(ProtoField.uint64, "test.uint64_14", nil, base.DEC, nil, "-1") -- 0xFFFFFFFFFFFFFFFF
testlib.test(OTHER,"ProtoField-uint64-mask-negative", success)

success = pcall(ProtoField.uint64, "test.uint64_15", nil, base.DEC, nil)
testlib.test(OTHER,"ProtoField-uint64-mask-none", success)

success = pcall(ProtoField.uint64, "test.uint64_16", nil, base.DEC, nil, nil)
testlib.test(OTHER,"ProtoField-uint64-mask-nil", success)


-- Field name: empty, illegal, incompatible
success = pcall(ProtoField.int8, nil, "empty field name 1")
testlib.test(OTHER,"ProtoField-empty-field-name-1", not success)

success = pcall(ProtoField.int8, "", "empty field name 2")
testlib.test(OTHER,"ProtoField-empty-field-name-2", not success)

success = pcall(ProtoField.int8, "test.$", "illegal field name")
testlib.test(OTHER,"ProtoField-illegal-field-name", not success)

success = pcall(ProtoField.int8, "frame.time", "incompatible field name")
testlib.test(OTHER,"ProtoField-incompatible-field-name", not success)

-- Actual name: empty
success = pcall(ProtoField.int8, "test.empty_name_1")
testlib.test(OTHER,"ProtoField-empty-name-1", success)  -- will use abbrev

success = pcall(ProtoField.int8, "test.empty_name_2", "")
testlib.test(OTHER,"ProtoField-empty-name-2", not success)

-- Signed integer base values, only base.DEC should work
success = pcall(ProtoField.int8, "test.int.base_none", "int base NONE", base.NONE)
testlib.test(OTHER,"ProtoField-int-base-none", not success)

success = pcall(ProtoField.int8, "test.int.base_dec", "int base DEC", base.DEC)
testlib.test(OTHER,"ProtoField-int-base-dec", success)

success = pcall(ProtoField.int8, "test.int.base_hex", "int base HEX", base.HEX)
testlib.test(OTHER,"ProtoField-int-base-hex", not success)

success = pcall(ProtoField.int8, "test.int.base_oct", "int base OCT", base.OCT)
testlib.test(OTHER,"ProtoField-int-base-oct", not success)

success = pcall(ProtoField.int8, "test.int.base_dec_hex", "int base DEC_HEX", base.DEC_HEX)
testlib.test(OTHER,"ProtoField-int-base-dec-hex", not success)

success = pcall(ProtoField.int8, "test.int.base_hex_dec", "int base HEX_DEC", base.HEX_DEC)
testlib.test(OTHER,"ProtoField-int-base-hex-dec", not success)

-- Passing no table should not work
success = pcall(ProtoField.uint16, "test.bad0", "Bad0", base.UNIT_STRING)
testlib.test(OTHER,"ProtoField-unitstring-no-table", not success)

-- Passing an empty table should not work
success = pcall(ProtoField.uint16, "test.bad1", "Bad1", base.UNIT_STRING, {})
testlib.test(OTHER,"ProtoField-unitstring-empty-table", not success)

-- Passing userdata should not work
success = pcall(ProtoField.uint16, "test.bad2", "Bad2", base.UNIT_STRING, {test_proto})
testlib.test(OTHER,"ProtoField-unitstring-userdata", not success)

-- Too many items are not supported
success = pcall(ProtoField.uint16, "test.bad3", "Bad3", base.UNIT_STRING, {"too", "many", "items"})
testlib.test(OTHER,"ProtoField-unitstring-too-many-items", not success)

-- base.SPECIAL_VALS
success = pcall(ProtoField.uint16, "test.special_vals", "SPECIAL_VALS base with empty table", base.DEC | base.SPECIAL_VALS, {})
testlib.test(OTHER,"ProtoField-special-vals", success)
success = pcall(ProtoField.uint16, "test.special_vals.no_table", "SPECIAL_VALS base with range string", base.DEC | base.RANGE_STRING | base.SPECIAL_VALS, {{0, 1, "Value"}})
testlib.test(OTHER,"ProtoField-special-vals-with-range-string", success)
success = pcall(ProtoField.uint16, "test.special_vals.unitstring", "SPECIAL_VALS base with unit string", base.DEC | base.UNIT_STRING | base.SPECIAL_VALS, {" sec", " secs"})
testlib.test(OTHER,"ProtoField-special-vals-with-unitstring", not success)
success = pcall(ProtoField.uint16, "test.special_vals.no_table", "SPECIAL_VALS base without table", base.DEC | base.SPECIAL_VALS)
testlib.test(OTHER,"ProtoField-special-vals-no-table", not success)


local numinits = 0
function test_proto.init()
    numinits = numinits + 1
    if numinits == 2 then
        testlib.getResults()
    end
end

-- Test expected text with singular and plural forms
function test_proto.dissector(tvb, pinfo, tree)
    local ti_time
    local ti_distance
    testlib.countPacket(FRAME)

    local tvb1 = ByteArray.new("00 00"):tvb("Tvb1")
    ti_time = tree:add(test_proto.fields.time_field, tvb1())
    ti_distance = tree:add(test_proto.fields.dist_field, tvb1())
    if tree.visible then
        testlib.test(PER_FRAME,"Time: 0 secs", ti_time.text == "Time: 0 secs")
        testlib.test(PER_FRAME,"Distance: 0 km", ti_distance.text == "Distance: 0 km")
    else
        testlib.test(PER_FRAME,"Time: 0 secs", ti_time.text == nil)
        testlib.test(PER_FRAME,"Distance: 0 km", ti_distance.text == nil)
    end

    local tvb2 = ByteArray.new("00 01"):tvb("Tvb2")
    ti_time = tree:add(test_proto.fields.time_field, tvb2())
    ti_distance = tree:add(test_proto.fields.dist_field, tvb2())
    if tree.visible then
        testlib.test(PER_FRAME,"Time: 1 sec", ti_time.text == "Time: 1 sec")
        testlib.test(PER_FRAME,"Distance: 1 km", ti_distance.text == "Distance: 1 km")
    else
        testlib.test(PER_FRAME,"Time: 1 sec", ti_time.text == nil)
        testlib.test(PER_FRAME,"Distance: 1 km", ti_distance.text == nil)
    end

    local tvb3 = ByteArray.new("ff ff"):tvb("Tvb3")
    ti_time = tree:add(test_proto.fields.time_field, tvb3())
    ti_distance = tree:add(test_proto.fields.dist_field, tvb3())
    if tree.visible then
        testlib.test(PER_FRAME,"Time: 65535 secs", ti_time.text == "Time: 65535 secs")
        testlib.test(PER_FRAME,"Distance: 65535 km", ti_distance.text == "Distance: 65535 km")
    else
        testlib.test(PER_FRAME,"Time: 65535 secs", ti_time.text == nil)
        testlib.test(PER_FRAME,"Distance: 65535 km", ti_distance.text == nil)
    end

    ti = tree:add(test_proto.fields.filtered_field, tvb2())
    -- Note that this file should be loaded in tshark twice. Once with a visible
    -- tree (-V) and once without a visible tree.
    if tree.visible then
        -- Tree is visible so both fields should be referenced
        testlib.test(PER_FRAME,"Visible tree: Time is referenced", tree:referenced(test_proto.fields.time_field) == true)
        testlib.test(PER_FRAME,"Visible tree: Filtered field is referenced", tree:referenced(test_proto.fields.filtered_field) == true)
    else
        -- Tree is not visible so only the field that appears in a filter should be referenced
        testlib.test(PER_FRAME,"Invisible tree: Time is NOT referenced", tree:referenced(test_proto.fields.time_field) == false)
        testlib.test(PER_FRAME,"Invisible tree: Filtered field is referenced", tree:referenced(test_proto.fields.filtered_field) == true)
    end
    testlib.pass(FRAME)
end

DissectorTable.get("udp.port"):add("65333,65346", test_proto)
