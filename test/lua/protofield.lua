----------------------------------------
-- script-name: protofield.lua
-- This is based on the dissector.lua example script, which is also used for testing.
-- Unlike that one, this one is purely for testing even more things, notably
-- the ProtoField API.
----------------------------------------

------------- general test helper funcs ------------
local OTHER = "other"

local total_tests = 0
local function getTotal()
    return total_tests
end

local passed = {}
local function setPassed(name)
    if not passed[name] then
        passed[name] = 1
    else
        passed[name] = passed[name] + 1
    end
    total_tests = total_tests + 1
end

local fail_count = 0
local function setFailed(name)
    fail_count = fail_count + 1
    total_tests = total_tests + 1
end

-- expected number of runs
local taptests = { [OTHER]=38 }
local function getResults()
    print("\n-----------------------------\n")
    for k,v in pairs(taptests) do
        if v ~= 0 and passed[k] ~= v then
            print("Something didn't run or ran too much... tests failed!")
            print("Dissector type "..k.." expected: "..v..", but got: "..tostring(passed[k]))
            return false
        end
    end
    print("All tests passed!\n\n")
    return true
end

local function test(type,name, ...)
    io.stdout:write("test "..type.."-->"..name.."-"..getTotal().."...")
    if (...) == true then
        setPassed(type)
        io.stdout:write("passed\n")
        return true
    else
        setFailed(type)
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

------------- test script ------------

----------------------------------
-- modify original test function for now, kinda sorta
local orig_test = test
test = function (...)
    return orig_test(OTHER,...)
end

----------------------------------------
local test_proto = Proto.new("test", "Test Proto")
test_proto.fields.time_field = ProtoField.uint16("test.time", "Time", base.UNIT_STRING, {" sec", " secs"})
test_proto.fields.dist_field = ProtoField.uint16("test.dist", "Distance", base.UNIT_STRING, {" km"})
test_proto.fields.filtered_field = ProtoField.uint16("test.filtered", "Filtered Field", base.DEC)

-- Field type: CHAR
success = pcall(ProtoField.new, "char", "test.char0", ftypes.CHAR)
test("ProtoField-char", success)

success = pcall(ProtoField.new, "char base NONE without valuestring", "test.char1", ftypes.CHAR, nil, base.NONE)
test("ProtoField-char-without-valuestring", not success)

success = pcall(ProtoField.new, "char base NONE with valuestring", "test.char2", ftypes.CHAR, {1, "Value"}, base.NONE)
test("ProtoField-char-with-valuestring", success)

success = pcall(ProtoField.new, "char base DEC", "test.char3", ftypes.CHAR, nil, base.DEC)
test("ProtoField-char-base-dec", not success)

success = pcall(ProtoField.new, "char base UNIT_STRING", "test.char4", ftypes.CHAR, {" m"}, base.UNIT_STRING)
test("ProtoField-char-unit-string", not success)

success = pcall(ProtoField.new, "char base RANGE_STRING", "test.char5", ftypes.CHAR, {{1, 2, "Value"}}, base.RANGE_STRING)
test("ProtoField-char-range-string", success)

-- Field name: empty, illegal, incompatible
success = pcall(ProtoField.int8, nil, "empty field name 1")
test("ProtoField-empty-field-name-1", not success)

success = pcall(ProtoField.int8, "", "empty field name 2")
test("ProtoField-empty-field-name-2", not success)

success = pcall(ProtoField.int8, "test.$", "illegal field name")
test("ProtoField-illegal-field-name", not success)

success = pcall(ProtoField.int8, "frame.time", "incompatible field name")
test("ProtoField-incompatible-field-name", not success)

-- Actual name: empty
success = pcall(ProtoField.int8, "test.empty_name_1")
test("ProtoField-empty-name-1", success)  -- will use abbrev

success = pcall(ProtoField.int8, "test.empty_name_2", "")
test("ProtoField-empty-name-2", not success)

-- Signed integer base values, only base.DEC should work
success = pcall(ProtoField.int8, "test.int.base_none", "int base NONE", base.NONE)
test("ProtoField-int-base-none", not success)

success = pcall(ProtoField.int8, "test.int.base_dec", "int base DEC", base.DEC)
test("ProtoField-int-base-dec", success)

success = pcall(ProtoField.int8, "test.int.base_hex", "int base HEX", base.HEX)
test("ProtoField-int-base-hex", not success)

success = pcall(ProtoField.int8, "test.int.base_oct", "int base OCT", base.OCT)
test("ProtoField-int-base-oct", not success)

success = pcall(ProtoField.int8, "test.int.base_dec_hex", "int base DEC_HEX", base.DEC_HEX)
test("ProtoField-int-base-dec-hex", not success)

success = pcall(ProtoField.int8, "test.int.base_hex_dec", "int base HEX_DEC", base.HEX_DEC)
test("ProtoField-int-base-hex-dec", not success)

-- Passing no table should not work
success = pcall(ProtoField.uint16, "test.bad0", "Bad0", base.UNIT_STRING)
test("ProtoField-unitstring-no-table", not success)

-- Passing an empty table should not work
success = pcall(ProtoField.uint16, "test.bad1", "Bad1", base.UNIT_STRING, {})
test("ProtoField-unitstring-empty-table", not success)

-- Passing userdata should not work
success = pcall(ProtoField.uint16, "test.bad2", "Bad2", base.UNIT_STRING, {test_proto})
test("ProtoField-unitstring-userdata", not success)

-- Too many items are not supported
success = pcall(ProtoField.uint16, "test.bad3", "Bad3", base.UNIT_STRING, {"too", "many", "items"})
test("ProtoField-unitstring-too-many-items", not success)

local numinits = 0
function test_proto.init()
    numinits = numinits + 1
    if numinits == 2 then
        getResults()
    end
end

-- Test expected text with singular and plural forms
function test_proto.dissector(tvb, pinfo, tree)
    local ti

    local tvb1 = ByteArray.new("00 00"):tvb("Tvb1")
    ti = tree:add(test_proto.fields.time_field, tvb1())
    test("Time: 0 secs", ti.text == "Time: 0 secs")
    ti = tree:add(test_proto.fields.dist_field, tvb1())
    test("Distance: 0 km", ti.text == "Distance: 0 km")

    local tvb2 = ByteArray.new("00 01"):tvb("Tvb2")
    ti = tree:add(test_proto.fields.time_field, tvb2())
    test("Time: 1 sec", ti.text == "Time: 1 sec")
    ti = tree:add(test_proto.fields.dist_field, tvb2())
    test("Distance: 1 km", ti.text == "Distance: 1 km")

    local tvb3 = ByteArray.new("ff ff"):tvb("Tvb3")
    ti = tree:add(test_proto.fields.time_field, tvb3())
    test("Time: 65535 secs", ti.text == "Time: 65535 secs")
    ti = tree:add(test_proto.fields.dist_field, tvb3())
    test("Distance: 65535 km", ti.text == "Distance: 65535 km")

    ti = tree:add(test_proto.fields.filtered_field, tvb2())
    -- Note that this file should be loaded in tshark twice. Once with a visible
    -- tree (-V) and once without a visible tree.
    if tree.visible then
        -- Tree is visible so both fields should be referenced
        test("Visible tree: Time is referenced", tree:referenced(test_proto.fields.time_field) == true)
        test("Visible tree: Filtered field is referenced", tree:referenced(test_proto.fields.filtered_field) == true)
    else
        -- Tree is not visible so only the field that appears in a filter should be referenced
        test("Invisible tree: Time is NOT referenced", tree:referenced(test_proto.fields.time_field) == false)
        test("Invisible tree: Filtered field is referenced", tree:referenced(test_proto.fields.filtered_field) == true)
    end
end

DissectorTable.get("udp.port"):add(65333, test_proto)
