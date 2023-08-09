--[[
    The tree:add_packet_field() method returns a value and offset in addition to a tree item.
    This file tests whether the value and offset are correct. As for the value,
    its correctness is tested in several ways for a given input.

    1. The returned value should match a precomputed value

    2. The returned value should match the value obtained from a Field object
        right after tree:add_packet_field() is called

    3. The returned value should match the value obtained from a Field object
        right after tree:add() is called with the same input as tree:add_packet_field()

    4. The returned value should match the value obtained from the corresponding value function
        called on the input tvbrange

    There are some incompatibilties and limitations due to handling of encodings.
    Incompatibilities are noted with the text INCOMPATIBILITY in a nearby comment.
]]

local field_setup = require "field_setup"

--[[
    This dissector expects a capture with at least one packet on UDP 65333.
    All the actual test data is synthetic.
]]--
local myproto = Proto("test", "Test")

field_data = field_setup(myproto, "test")

function hexlify_string(s)
    local sep = ""
    local hx = ""
    for i=1,#s do
        hx = hx .. sep .. string.format("%02x", s:byte(i))
        sep = " "
    end
    return hx
end

--[[
    Ensure the value is represented in a way that shows up when printed.
    It is assumed the string representation is relatively short.

    The test suite will report an error if we print invalid utf8 for any reason.
    We work around this by passing a substitution string used when the real
    string has invalid utf8. We also print the output bytes in hex after the string,
    and those bytes are always faithful to the real output.
]]--
function format_value_for_print(v, substitution)
    local t = type(v)
    local s
    if t == "string" then
        local hx = hexlify_string(v)
        if substitution ~= nil then
            s = string.format("(invalid utf8) \"%s\" [%s]", substitution, hx)
        else
            s = string.format("\"%s\" [%s]", v, hx)
        end

    else
        s = tostring(v)
    end
    return string.format("(%s) %s", type(v), s)
end

function format_encoding_for_print(enc)

    local char_enc = "ASCII"
    if bit.band(enc, ENC_UTF_16) ~= 0 then
        char_enc = "UTF-16"
    end

    local enc_enc = "BE"
    if bit.band(enc, ENC_LITTLE_ENDIAN) ~= 0 then
        end_enc = "LE"
    end

    if enc == ENC_ISO_8601_DATE_TIME then
        char_enc = "ISO_8601"
        end_enc = "-"
    end

    return string.format("%s %s", char_enc, end_enc)
end

function print_test_data(test_data)
    print(string.format("TEST: using field type: %s", test_data.field_type))
    if test_data.hexlify then
        print(string.format("TEST: input was hexlified from: \"%s\"", test_data.original_input))
    end
    print(string.format("TEST: using data: [%s]", test_data.input))
    print(string.format("TEST: using offset: %d", test_data.input_offset))
    print(string.format("TEST: using encoding: %s", format_encoding_for_print(test_data.encoding)))
    print()
end

function general_equality_test(a, b)
    return a == b
end

--equal or both nan
function float_equality_test(a, b)
    return a == b or (a ~= a and b ~= b)
end

function recent_field_value(t)
    local values = {field_data[t].value_field()}
    return values[#values].value
end

function add_packet_field_returns_precomputed_value(test_data)

    print(string.format("  EXPECT: precomputed return value: %s", format_value_for_print(test_data.expect_precomputed)))
    print(string.format("  OUTPUT: add_packet_field returned value: %s", format_value_for_print(test_data.returned_value)))

    if test_data.equality_function(test_data.returned_value, test_data.expect_precomputed) then
        print("  PASS: the return value is correct")
        print()
        return true
    end

    print("  FAIL: the returned value is incorrect")
    print()
    return false
end

function add_packet_field_then_value_field_returns_expected_value(test_data)

    print(string.format("  EXPECT: value field value %s", format_value_for_print(test_data.expect_add_pf_field_value)))
    print(string.format("  OUTPUT: value field after tree:add_packet_field() returned: %s",
        format_value_for_print(test_data.returned_add_pf_field_value)))

    local incompatible = test_data.expect_add_pf_field_value ~= test_data.expect_precomputed
    if incompatible then
        print("  WARNING: the value field does not return the same value as the other implementations")
    end
    if test_data.equality_function(test_data.returned_add_pf_field_value, test_data.expect_add_pf_field_value) then
        print("  PASS: the value field is correct")
        print()
        return true
    end

    print("  FAIL: the value field is incorrect")
    print()
    return false
end

function tree_add_then_value_field_returns_expected_value(test_data)

    if test_data.skip_tree_add_test then
        print("  SKIP: " .. test_data.skip_tree_add_test_message)
        print()
        return true
    end

    print(string.format("  EXPECT: value field value %s", format_value_for_print(test_data.expect_add_field_value)))
    print(string.format("  OUTPUT: value field after tree:add() returned: %s",
        format_value_for_print(test_data.returned_add_field_value)))

    local incompatible = test_data.expect_add_field_value ~= test_data.expect_precomputed
    if incompatible then
        print("  WARNING: the value field does not return the same value as the other implementations")
    end
    if test_data.equality_function(test_data.returned_add_field_value, test_data.expect_add_field_value) then
        print("  PASS: the value field is correct")
        print()
        return true
    end

    print("  FAIL: the value field is incorrect")
    print()
    return false

end

--[[
    The tvbrange:string() function can return invalid utf8 even when the input is valid.
]]
function tvbrange_returns_expected_value(test_data)

    if test_data.tvbr_fn == nil then
        print("  SKIP: no tvbrange function for this field type")
        print()
        return true
    end

    local tvbr_value, tvbr_fn_printable = test_data.tvbr_fn(test_data.input_tvbrange, test_data.encoding)
    local pass = test_data.equality_function(tvbr_value, test_data.expect_tvbrange_value)
    local incompatible = test_data.expect_tvbrange_value ~= test_data.expect_precomputed
    local tvbr_value_printable = format_value_for_print(tvbr_value)
    local expect_value_printable = format_value_for_print(test_data.expect_tvbrange_value, test_data.expect_tvbrange_value_printable)
    if pass then
        --if the outputs are equal, then the substitute is useable for both
        tvbr_value_printable = format_value_for_print(tvbr_value, test_data.expect_tvbrange_value_printable)
    end

    print(string.format("  TEST: using tvbrange function %s", tvbr_fn_printable))
    print(string.format("  EXPECT: tvbrange value %s", expect_value_printable))
    print(string.format("  OUTPUT: tvbrange returned %s", tvbr_value_printable))
    if incompatible then
        print("  WARNING: the tvbr function is not compatible with the other implementations")
    end

    if pass then
        print("  PASS: the the tvbr function works as expected")
        print()
        return true
    end

    print("  FAIL: the the tvbr function works as expected")
    print()
    return false
end

function add_packet_field_returns_correct_offset(test_data)

    print(string.format("  EXPECT: offset %d", test_data.expect_offset))
    print(string.format("  OUTPUT: add_packet_field returned offset %d", test_data.returned_offset))

    if test_data.returned_offset == test_data.expect_offset then
        print("  PASS: the returned offset is correct")
        print()
        return true
    end

    print("  FAIL: the returned offset is incorrect")
    print()
    return false
end

function add_packet_field_all_tests(tree, test_data)
    print_test_data(test_data)
    local ret = true
        and add_packet_field_returns_precomputed_value(test_data)
        and add_packet_field_then_value_field_returns_expected_value(test_data)
        and tree_add_then_value_field_returns_expected_value(test_data)
        and tvbrange_returns_expected_value(test_data)
        and add_packet_field_returns_correct_offset(test_data)
    return ret
end

function generate_test_data_for_case(tree, field_type, case, tvbr_fn, equality_function, use_offset)

    local input = case.input
    if case.hexlify then
        input = hexlify_string(case.input)
    end

    local input_byte_length = string.len(input:gsub(" ", "")) / 2
    local input_offset = 0
    if use_offset then
        input = "77 " .. input
        input_offset = 1
    end

    local input_tvb = ByteArray.new(input):tvb()
    local input_tvbrange

    if case.fake_input_length == nil then
        input_tvbrange = input_tvb(input_offset, input_byte_length)
    else
        input_tvbrange = input_tvb(input_offset, case.fake_input_length)
    end

    local t = field_data[field_type]
    local add_pf_leaf, returned_value, returned_offset = tree:add_packet_field(t.packet_field, input_tvbrange, case.encoding)
    local add_pf_field_value = recent_field_value(field_type)

    local add_leaf = nil
    local add_field_value = nil
    local skip_tree_add_test_message = nil
    local skip_tree_add_test = false

    if case.encoding == ENC_ASCII + ENC_BIG_ENDIAN then
        add_leaf = tree:add(t.packet_field, input_tvbrange)
        add_field_value = recent_field_value(field_type)
    elseif case.encoding == ENC_ASCII + ENC_LITTLE_ENDIAN then
        add_leaf = tree:add_le(t.packet_field, input_tvbrange)
        add_field_value = recent_field_value(field_type)
    else
        skip_tree_add_test = true
        skip_tree_add_test_message = "tree:add() only uses ASCII encoding"
    end

    local expect_add_pf_field_value = case.output
    if case.incompatible_add_pf_field then
        expect_add_pf_field_value = case.expect_add_pf_field_value
    end

    local expect_add_field_value = case.output
    if case.incompatible_add_field then
        expect_add_field_value = case.expect_add_field_value
    end

    local expect_tvbrange_value = case.output
    if case.incompatible_tvbrange then
        expect_tvbrange_value = case.expect_tvbrange_value
    end

    local expect_offset = input_byte_length + input_offset
    if case.variable_input_length then
        expect_offset = case.input_length + input_offset
    end

    return {
        field_type = field_type,
        hexlify = case.hexlify,
        original_input = case.input,
        input = input,
        input_offset = input_offset,
        input_tvbrange = input_tvbrange,
        encoding = case.encoding,

        returned_value = returned_value,
        returned_offset = returned_offset,
        returned_add_pf_field_value = add_pf_field_value,
        returned_add_field_value = add_field_value,

        tvbr_fn = tvbr_fn,
        equality_function = equality_function,
        expect_precomputed = case.output,
        expect_add_pf_field_value = expect_add_pf_field_value,

        expect_add_field_value = expect_add_field_value,
        skip_tree_add_test = skip_tree_add_test,
        skip_tree_add_test_message = skip_tree_add_test_message,

        expect_tvbrange_value = expect_tvbrange_value,
        expect_tvbrange_value_printable = case.expect_tvbrange_value_printable,
        expect_offset = expect_offset
    }
end

function run_test_cases_all_tests(tree, field_type, test_cases, tvbr_fn, equality_function)
    local test_data
    for _ , case in ipairs(test_cases) do
        test_data = generate_test_data_for_case(tree, field_type, case, tvbr_fn, equality_function, true)
        if not add_packet_field_all_tests(tree, test_data) then
            return false
        end

        test_data = generate_test_data_for_case(tree, field_type, case, tvbr_fn, equality_function, false)
        if not add_packet_field_all_tests(tree, test_data) then
            return false
        end
    end

    return true
end

function simple_integer_tests(tree)
    local uint8_test_cases = {
        {input = "ff", encoding = ENC_LITTLE_ENDIAN, output = 0xff},
        {input = "00", encoding = ENC_LITTLE_ENDIAN, output = 0x00},
        {input = "ff", encoding = ENC_BIG_ENDIAN,    output = 0xff},
        {input = "00", encoding = ENC_BIG_ENDIAN,    output = 0x00},
    }

    local uint16_test_cases = {
        {input = "ff 00", encoding = ENC_LITTLE_ENDIAN, output = 0x00ff},
        {input = "00 ff", encoding = ENC_LITTLE_ENDIAN, output = 0xff00},
        {input = "ff 00", encoding = ENC_BIG_ENDIAN,    output = 0xff00},
        {input = "00 ff", encoding = ENC_BIG_ENDIAN,    output = 0x00ff},
    }

    local uint24_test_cases = {
        {input = "ff 00 00", encoding = ENC_LITTLE_ENDIAN, output = 0x0000ff},
        {input = "00 ff 00", encoding = ENC_LITTLE_ENDIAN, output = 0x00ff00},
        {input = "00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = 0xff0000},
        {input = "ff 00 00", encoding = ENC_BIG_ENDIAN,    output = 0xff0000},
        {input = "00 ff 00", encoding = ENC_BIG_ENDIAN,    output = 0x00ff00},
        {input = "00 00 ff", encoding = ENC_BIG_ENDIAN,    output = 0x0000ff},
    }

    local uint32_test_cases = {
        {input = "ff 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = 0x000000ff},
        {input = "00 ff 00 00", encoding = ENC_LITTLE_ENDIAN, output = 0x0000ff00},
        {input = "00 00 ff 00", encoding = ENC_LITTLE_ENDIAN, output = 0x00ff0000},
        {input = "00 00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = 0xff000000},
        {input = "ff 00 00 00", encoding = ENC_BIG_ENDIAN,    output = 0xff000000},
        {input = "00 ff 00 00", encoding = ENC_BIG_ENDIAN,    output = 0x00ff0000},
        {input = "00 00 ff 00", encoding = ENC_BIG_ENDIAN,    output = 0x0000ff00},
        {input = "00 00 00 ff", encoding = ENC_BIG_ENDIAN,    output = 0x000000ff},
    }

    function tvbr_uint (tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_uint(), "le_uint()"
        else
            return tvbr:uint(), "uint()"
        end
    end

    local int8_test_cases = {
        {input = "ff", encoding = ENC_LITTLE_ENDIAN, output = -0x01},
        {input = "00", encoding = ENC_LITTLE_ENDIAN, output =  0x00},
        {input = "ff", encoding = ENC_BIG_ENDIAN,    output = -0x01},
        {input = "00", encoding = ENC_BIG_ENDIAN,    output =  0x00},
    }

    local int16_test_cases = {
        {input = "ff 00", encoding = ENC_LITTLE_ENDIAN, output =  0x00ff},
        {input = "00 ff", encoding = ENC_LITTLE_ENDIAN, output = -0x0100},
        {input = "ff 00", encoding = ENC_BIG_ENDIAN,    output = -0x0100},
        {input = "00 ff", encoding = ENC_BIG_ENDIAN,    output =  0x00ff},
    }

    local int24_test_cases = {
        {input = "ff 00 00", encoding = ENC_LITTLE_ENDIAN, output =  0x0000ff},
        {input = "00 ff 00", encoding = ENC_LITTLE_ENDIAN, output =  0x00ff00},
        {input = "00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = -0x010000},
        {input = "ff 00 00", encoding = ENC_BIG_ENDIAN,    output = -0x010000},
        {input = "00 ff 00", encoding = ENC_BIG_ENDIAN,    output =  0x00ff00},
        {input = "00 00 ff", encoding = ENC_BIG_ENDIAN,    output =  0x0000ff},
    }

    local int32_test_cases = {
        {input = "ff 00 00 00", encoding = ENC_LITTLE_ENDIAN, output =  0x000000ff},
        {input = "00 ff 00 00", encoding = ENC_LITTLE_ENDIAN, output =  0x0000ff00},
        {input = "00 00 ff 00", encoding = ENC_LITTLE_ENDIAN, output =  0x00ff0000},
        {input = "00 00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = -0x01000000},
        {input = "ff 00 00 00", encoding = ENC_BIG_ENDIAN,    output = -0x01000000},
        {input = "00 ff 00 00", encoding = ENC_BIG_ENDIAN,    output =  0x00ff0000},
        {input = "00 00 ff 00", encoding = ENC_BIG_ENDIAN,    output =  0x0000ff00},
        {input = "00 00 00 ff", encoding = ENC_BIG_ENDIAN,    output =  0x000000ff},
    }

    function tvbr_int(tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_int(), "le_int()"
        else
            return tvbr:int(), "int()"
        end
    end

    return true
        and run_test_cases_all_tests(tree, "uint8",  uint8_test_cases,  tvbr_uint, general_equality_test)
        and run_test_cases_all_tests(tree, "uint16", uint16_test_cases, tvbr_uint, general_equality_test)
        and run_test_cases_all_tests(tree, "uint24", uint24_test_cases, tvbr_uint, general_equality_test)
        and run_test_cases_all_tests(tree, "uint32", uint32_test_cases, tvbr_uint, general_equality_test)

        and run_test_cases_all_tests(tree, "int8",  int8_test_cases,  tvbr_int, general_equality_test)
        and run_test_cases_all_tests(tree, "int16", int16_test_cases, tvbr_int, general_equality_test)
        and run_test_cases_all_tests(tree, "int24", int24_test_cases, tvbr_int, general_equality_test)
        and run_test_cases_all_tests(tree, "int32", int32_test_cases, tvbr_int, general_equality_test)
end

function integer64_tests(tree)

    local uint64_test_cases = {
        {input = "ff 00 00 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x000000ff, 0x00000000)},
        {input = "00 ff 00 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x0000ff00, 0x00000000)},
        {input = "00 00 ff 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x00ff0000, 0x00000000)},
        {input = "00 00 00 ff 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0xff000000, 0x00000000)},
        {input = "00 00 00 00 ff 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x00000000, 0x000000ff)},
        {input = "00 00 00 00 00 ff 00 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x00000000, 0x0000ff00)},
        {input = "00 00 00 00 00 00 ff 00", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x00000000, 0x00ff0000)},
        {input = "00 00 00 00 00 00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = UInt64(0x00000000, 0xff000000)},
        {input = "ff 00 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x00000000, 0xff000000)},
        {input = "00 ff 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x00000000, 0x00ff0000)},
        {input = "00 00 ff 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x00000000, 0x0000ff00)},
        {input = "00 00 00 ff 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x00000000, 0x000000ff)},
        {input = "00 00 00 00 ff 00 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0xff000000, 0x00000000)},
        {input = "00 00 00 00 00 ff 00 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x00ff0000, 0x00000000)},
        {input = "00 00 00 00 00 00 ff 00", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x0000ff00, 0x00000000)},
        {input = "00 00 00 00 00 00 00 ff", encoding = ENC_BIG_ENDIAN,    output = UInt64(0x000000ff, 0x00000000)},
    }

    function tvbr_uint(tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_uint64(), "le_uint64()"
        else
            return tvbr:uint64(), "uint64()"
        end
    end

    local int64_test_cases = {
        {input = "ff 00 00 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x000000ff, 0x00000000)},
        {input = "00 ff 00 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x0000ff00, 0x00000000)},
        {input = "00 00 ff 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x00ff0000, 0x00000000)},
        {input = "00 00 00 ff 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0xff000000, 0x00000000)},
        {input = "00 00 00 00 ff 00 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x00000000, 0x000000ff)},
        {input = "00 00 00 00 00 ff 00 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x00000000, 0x0000ff00)},
        {input = "00 00 00 00 00 00 ff 00", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x00000000, 0x00ff0000)},
        {input = "00 00 00 00 00 00 00 ff", encoding = ENC_LITTLE_ENDIAN, output = Int64(0x00000000, 0xff000000)},
        {input = "ff 00 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x00000000, 0xff000000)},
        {input = "00 ff 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x00000000, 0x00ff0000)},
        {input = "00 00 ff 00 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x00000000, 0x0000ff00)},
        {input = "00 00 00 ff 00 00 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x00000000, 0x000000ff)},
        {input = "00 00 00 00 ff 00 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0xff000000, 0x00000000)},
        {input = "00 00 00 00 00 ff 00 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x00ff0000, 0x00000000)},
        {input = "00 00 00 00 00 00 ff 00", encoding = ENC_BIG_ENDIAN,    output = Int64(0x0000ff00, 0x00000000)},
        {input = "00 00 00 00 00 00 00 ff", encoding = ENC_BIG_ENDIAN,    output = Int64(0x000000ff, 0x00000000)},
    }

    function tvbr_int(tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_int64(), "le_int64()"
        else
            return tvbr:int64(), "int64()"
        end
    end

    return true
        and run_test_cases_all_tests(tree, "uint64", uint64_test_cases, tvbr_uint, general_equality_test)
        and run_test_cases_all_tests(tree, "int64",  int64_test_cases,  tvbr_int, general_equality_test)
end

function string_tests(tree)

    local ABC_ascii =   "41 42 43"
    local ABCzD_ascii = "41 42 43 00 44"

    local SHARK_16_little =   "b5 30 e1 30"
    local SHARKzSA_16_little = "b5 30 e1 30 00 00 b5 30"

    local SHARK_16_big =   "30 b5 30 e1"
    local SHARKzSA_16_big = "30 b5 30 e1 00 00 30 b5"

    local string_test_cases = {
        {input = ABC_ascii, encoding = ENC_ASCII, output = "ABC"},

        {input = ABCzD_ascii, encoding = ENC_ASCII, output = "ABC"},

        {input = SHARK_16_little, encoding = ENC_ASCII, output = "�0�0"},

        {input = SHARK_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ"},

        {input = SHARKzSA_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ"},

        {input = SHARK_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ"},

        {input = SHARKzSA_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ"},
    }

    function tvbr_string(tvbr, encoding)
        return tvbr:string(encoding), string.format("string(%s)", format_encoding_for_print(encoding))
    end

    --[[
        stringz computes its own input length by looking for null
        the input length includes the null, which is 2 bytes for utf16
    ]]--
    local stringz_tests = {

        {input = ABCzD_ascii, encoding = ENC_ASCII, output = "ABC",
            variable_input_length = true, input_length = 4
        },

        {input = SHARKzSA_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ",
            variable_input_length = true, input_length = 6,
        },

        {input = SHARKzSA_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ",
            variable_input_length = true, input_length = 6,
        },
    }

    function tvbr_stringz(tvbr, encoding)
        return tvbr:stringz(encoding), string.format("stringz(%s)", format_encoding_for_print(encoding))
    end

    local ustring_tests = {
        {input = SHARK_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ"},
        {input = SHARKzSA_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ"},
    }

    function tvbr_ustring(tvbr, encoding)
        return tvbr:ustring(), "ustring()"
    end

    local le_ustring_tests = {
        {input = SHARK_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ"},
        {input = SHARKzSA_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ"},
    }

    function tvbr_le_ustring(tvbr, encoding)
        return tvbr:le_ustring(), "le_ustring()"
    end

    local ustringz_tests = {
        {input = SHARKzSA_16_big, encoding = ENC_UTF_16 + ENC_BIG_ENDIAN, output = "サメ",
            variable_input_length = true, input_length = 6
        },
    }

    function tvbr_ustringz(tvbr, encoding)
        return tvbr:ustringz(), "ustringz()"
    end

    local le_ustringz_tests = {
        {input = SHARKzSA_16_little, encoding = ENC_UTF_16 + ENC_LITTLE_ENDIAN, output = "サメ",
            variable_input_length = true, input_length = 6
        },
    }

    function tvbr_le_ustringz(tvbr, encoding)
        return tvbr:le_ustringz(), "le_ustringz()"
    end

    return true
        and run_test_cases_all_tests(tree, "string",  string_test_cases,  tvbr_string,      general_equality_test)
        and run_test_cases_all_tests(tree, "stringz", stringz_tests,      tvbr_stringz,     general_equality_test)
        and run_test_cases_all_tests(tree, "string",  ustring_tests,      tvbr_ustring,     general_equality_test)
        and run_test_cases_all_tests(tree, "string",  le_ustring_tests,   tvbr_le_ustring,  general_equality_test)
        and run_test_cases_all_tests(tree, "stringz", ustringz_tests,     tvbr_ustringz,    general_equality_test)
        and run_test_cases_all_tests(tree, "stringz", le_ustringz_tests,  tvbr_le_ustringz, general_equality_test)
end

function bool_char_tests(tree)

    local bool_tests = {
        {input = "ff", encoding = ENC_BIG_ENDIAN, output = true},
        {input = "00", encoding = ENC_BIG_ENDIAN, output = false},
        {input = "01", encoding = ENC_BIG_ENDIAN, output = true},
        {input = "ff", encoding = ENC_LITTLE_ENDIAN, output = true},
        {input = "00", encoding = ENC_LITTLE_ENDIAN, output = false},
        {input = "01", encoding = ENC_LITTLE_ENDIAN, output = true},
    }

    local char_tests = {
        {input = "ff", encoding = ENC_BIG_ENDIAN, output = 0xff},
        {input = "00", encoding = ENC_BIG_ENDIAN, output = 0x00},
        {input = "30", encoding = ENC_BIG_ENDIAN, output = 0x30},
        {input = "ff", encoding = ENC_LITTLE_ENDIAN, output = 0xff},
        {input = "00", encoding = ENC_LITTLE_ENDIAN, output = 0x00},
        {input = "30", encoding = ENC_LITTLE_ENDIAN, output = 0x30},
    }

    return true
        and run_test_cases_all_tests(tree, "boolean", bool_tests, nil, general_equality_test)
        and run_test_cases_all_tests(tree, "char", char_tests, nil, general_equality_test)
end

function float_tests(tree)

    local be_float = {
        {input = "3c 00 00 00", encoding = ENC_BIG_ENDIAN, output =  0.0078125},
        {input = "bd a0 00 00", encoding = ENC_BIG_ENDIAN, output = -0.078125},
        {input = "3f 48 00 00", encoding = ENC_BIG_ENDIAN, output =  0.78125},
        {input = "c0 fa 00 00", encoding = ENC_BIG_ENDIAN, output = -7.8125},
        {input = "42 9c 40 00", encoding = ENC_BIG_ENDIAN, output =  78.125},
        {input = "c4 43 50 00", encoding = ENC_BIG_ENDIAN, output = -781.25},
        {input = "45 f4 24 00", encoding = ENC_BIG_ENDIAN, output =  7812.5},
        {input = "c7 98 96 80", encoding = ENC_BIG_ENDIAN, output = -78125.0},
        {input = "49 3e bc 20", encoding = ENC_BIG_ENDIAN, output =  781250.0},
        {input = "ca ee 6b 28", encoding = ENC_BIG_ENDIAN, output = -7812500.0},
        {input = "00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  0.0},
        {input = "80 00 00 00", encoding = ENC_BIG_ENDIAN, output = -0.0},
        {input = "7f c0 00 00", encoding = ENC_BIG_ENDIAN, output =  0/0},
        {input = "7f 80 00 00", encoding = ENC_BIG_ENDIAN, output =  1/0},
        {input = "ff 80 00 00", encoding = ENC_BIG_ENDIAN, output = -1/0},
    }

    local le_float = {
        {input = "00 00 00 3c", encoding = ENC_LITTLE_ENDIAN, output =  0.0078125},
        {input = "00 00 a0 bd", encoding = ENC_LITTLE_ENDIAN, output = -0.078125},
        {input = "00 00 48 3f", encoding = ENC_LITTLE_ENDIAN, output =  0.78125},
        {input = "00 00 fa c0", encoding = ENC_LITTLE_ENDIAN, output = -7.8125},
        {input = "00 40 9c 42", encoding = ENC_LITTLE_ENDIAN, output =  78.125},
        {input = "00 50 43 c4", encoding = ENC_LITTLE_ENDIAN, output = -781.25},
        {input = "00 24 f4 45", encoding = ENC_LITTLE_ENDIAN, output =  7812.5},
        {input = "80 96 98 c7", encoding = ENC_LITTLE_ENDIAN, output = -78125.0},
        {input = "20 bc 3e 49", encoding = ENC_LITTLE_ENDIAN, output =  781250.0},
        {input = "28 6b ee ca", encoding = ENC_LITTLE_ENDIAN, output = -7812500.0},
        {input = "00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output =  0.0},
        {input = "00 00 00 80", encoding = ENC_LITTLE_ENDIAN, output = -0.0},
        {input = "00 00 c0 7f", encoding = ENC_LITTLE_ENDIAN, output =  0/0},
        {input = "00 00 80 7f", encoding = ENC_LITTLE_ENDIAN, output =  1/0},
        {input = "00 00 80 ff", encoding = ENC_LITTLE_ENDIAN, output = -1/0},
    }

    local be_double = {
        {input = "3f 80 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  0.0078125},
        {input = "bf e9 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output = -0.78125},
        {input = "40 88 6a 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  781.25},
        {input = "c0 f3 12 d0 00 00 00 00", encoding = ENC_BIG_ENDIAN, output = -78125.0},
        {input = "41 92 a0 5f 20 00 00 00", encoding = ENC_BIG_ENDIAN, output =  78125000.0},
        {input = "c1 fd 1a 94 a2 00 00 00", encoding = ENC_BIG_ENDIAN, output = -7812500000.0},
        {input = "42 9c 6b f5 26 34 00 00", encoding = ENC_BIG_ENDIAN, output =  7812500000000.0},
        {input = "c3 06 34 57 85 d8 a0 00", encoding = ENC_BIG_ENDIAN, output = -781250000000000.0},
        {input = "43 a5 af 1d 78 b5 8c 40", encoding = ENC_BIG_ENDIAN, output =  7.8125e+17},
        {input = "c4 10 f0 cf 06 4d d5 92", encoding = ENC_BIG_ENDIAN, output = -7.8125e+19},
        {input = "00 00 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  0.0},
        {input = "80 00 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output = -0.0},
        {input = "7f f8 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  0/0},
        {input = "7f f0 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output =  1/0},
        {input = "ff f0 00 00 00 00 00 00", encoding = ENC_BIG_ENDIAN, output = -1/0},
    }

    local le_double = {
        {input = "00 00 00 00 00 00 80 3f", encoding = ENC_LITTLE_ENDIAN, output =  0.0078125},
        {input = "00 00 00 00 00 00 e9 bf", encoding = ENC_LITTLE_ENDIAN, output = -0.78125},
        {input = "00 00 00 00 00 6a 88 40", encoding = ENC_LITTLE_ENDIAN, output =  781.25},
        {input = "00 00 00 00 d0 12 f3 c0", encoding = ENC_LITTLE_ENDIAN, output = -78125.0},
        {input = "00 00 00 20 5f a0 92 41", encoding = ENC_LITTLE_ENDIAN, output =  78125000.0},
        {input = "00 00 00 a2 94 1a fd c1", encoding = ENC_LITTLE_ENDIAN, output = -7812500000.0},
        {input = "00 00 34 26 f5 6b 9c 42", encoding = ENC_LITTLE_ENDIAN, output =  7812500000000.0},
        {input = "00 a0 d8 85 57 34 06 c3", encoding = ENC_LITTLE_ENDIAN, output = -781250000000000.0},
        {input = "40 8c b5 78 1d af a5 43", encoding = ENC_LITTLE_ENDIAN, output =  7.8125e+17},
        {input = "92 d5 4d 06 cf f0 10 c4", encoding = ENC_LITTLE_ENDIAN, output = -7.8125e+19},
        {input = "00 00 00 00 00 00 00 00", encoding = ENC_LITTLE_ENDIAN, output =  0.0},
        {input = "00 00 00 00 00 00 00 80", encoding = ENC_LITTLE_ENDIAN, output = -0.0},
        {input = "00 00 00 00 00 00 f8 7f", encoding = ENC_LITTLE_ENDIAN, output =  0/0},
        {input = "00 00 00 00 00 00 f0 7f", encoding = ENC_LITTLE_ENDIAN, output =  1/0},
        {input = "00 00 00 00 00 00 f0 ff", encoding = ENC_LITTLE_ENDIAN, output = -1/0},
    }

    function tvbr_float(tvbr, encoding)
        return tvbr:float(), "float()"
    end

    function tvbr_le_float(tvbr, encoding)
        return tvbr:le_float(), "le_float()"
    end

    return true
        and run_test_cases_all_tests(tree, "float", be_float, tvbr_float, float_equality_test)
        and run_test_cases_all_tests(tree, "double", be_double, tvbr_float, float_equality_test)
        and run_test_cases_all_tests(tree, "float", le_float, tvbr_le_float, float_equality_test)
        and run_test_cases_all_tests(tree, "double", le_double, tvbr_le_float, float_equality_test)
end

function address_tests(tree)

    --INCOMPATIBILITY: value fields always assume big-endian encoding for IPv4 addresses
    local ipv4_test_cases = {
        {input = "01 00 00 00", encoding = ENC_LITTLE_ENDIAN, output    = Address.ip("0.0.0.1"),
            incompatible_add_pf_field = true, expect_add_pf_field_value = Address.ip("1.0.0.0"),
            incompatible_add_field = true, expect_add_field_value = Address.ip("1.0.0.0")
        },
        {input = "00 02 00 00", encoding = ENC_LITTLE_ENDIAN, output    = Address.ip("0.0.2.0"),
            incompatible_add_pf_field = true, expect_add_pf_field_value = Address.ip("0.2.0.0"),
            incompatible_add_field = true, expect_add_field_value = Address.ip("0.2.0.0")
        },
        {input = "00 00 03 00", encoding = ENC_LITTLE_ENDIAN, output    = Address.ip("0.3.0.0"),
            incompatible_add_pf_field = true, expect_add_pf_field_value = Address.ip("0.0.3.0"),
            incompatible_add_field = true, expect_add_field_value = Address.ip("0.0.3.0")
        },
        {input = "00 00 00 04", encoding = ENC_LITTLE_ENDIAN, output    = Address.ip("4.0.0.0"),
            incompatible_add_pf_field = true, expect_add_pf_field_value = Address.ip("0.0.0.4"),
            incompatible_add_field = true, expect_add_field_value = Address.ip("0.0.0.4")
        },
        {input = "01 00 00 00", encoding = ENC_BIG_ENDIAN,    output    = Address.ip("1.0.0.0")},
        {input = "00 02 00 00", encoding = ENC_BIG_ENDIAN,    output    = Address.ip("0.2.0.0")},
        {input = "00 00 03 00", encoding = ENC_BIG_ENDIAN,    output    = Address.ip("0.0.3.0")},
        {input = "00 00 00 04", encoding = ENC_BIG_ENDIAN,    output    = Address.ip("0.0.0.4")},
    }

    function tvbr_ipv4 (tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_ipv4(), "le_ipv4()"
        else
            return tvbr:ipv4(), "ipv4()"
        end
    end

    local ipv6_test_cases = {
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 0000 0000 00ff",
                      output = Address.ipv6("0000:0000:0000:0000:0000:0000:0000:00ff")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 0000 0000 ff00",
                      output = Address.ipv6("0000:0000:0000:0000:0000:0000:0000:ff00")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 0000 00ff 0000",
                      output = Address.ipv6("0000:0000:0000:0000:0000:0000:00ff:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 0000 ff00 0000",
                      output = Address.ipv6("0000:0000:0000:0000:0000:0000:ff00:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 00ff 0000 0000",
                      output = Address.ipv6("0000:0000:0000:0000:0000:00ff:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 0000 ff00 0000 0000",
                      output = Address.ipv6("0000:0000:0000:0000:0000:ff00:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 00ff 0000 0000 0000",
                      output = Address.ipv6("0000:0000:0000:0000:00ff:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 0000 ff00 0000 0000 0000",
                      output = Address.ipv6("0000:0000:0000:0000:ff00:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 00ff 0000 0000 0000 0000",
                      output = Address.ipv6("0000:0000:0000:00ff:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 0000 ff00 0000 0000 0000 0000",
                      output = Address.ipv6("0000:0000:0000:ff00:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 00ff 0000 0000 0000 0000 0000",
                      output = Address.ipv6("0000:0000:00ff:0000:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 0000 ff00 0000 0000 0000 0000 0000",
                      output = Address.ipv6("0000:0000:ff00:0000:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 00ff 0000 0000 0000 0000 0000 0000",
                      output = Address.ipv6("0000:00ff:0000:0000:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "0000 ff00 0000 0000 0000 0000 0000 0000",
                      output = Address.ipv6("0000:ff00:0000:0000:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "00ff 0000 0000 0000 0000 0000 0000 0000",
                      output = Address.ipv6("00ff:0000:0000:0000:0000:0000:0000:0000")},
        {encoding = ENC_BIG_ENDIAN, input = "ff00 0000 0000 0000 0000 0000 0000 0000",
                      output = Address.ipv6("ff00:0000:0000:0000:0000:0000:0000:0000")},
    }

    function tvbr_ipv6 (tvbr, encoding)
        return tvbr:ipv6(), "ipv6()"
    end

    local ether_test_cases = {
        {input = "ff 00 00 00 00 00", encoding = 0, output = Address.ether("ff:00:00:00:00:00")},
        {input = "00 ff 00 00 00 00", encoding = 0, output = Address.ether("00:ff:00:00:00:00")},
        {input = "00 00 ff 00 00 00", encoding = 0, output = Address.ether("00:00:ff:00:00:00")},
        {input = "00 00 00 ff 00 00", encoding = 0, output = Address.ether("00:00:00:ff:00:00")},
        {input = "00 00 00 00 ff 00", encoding = 0, output = Address.ether("00:00:00:00:ff:00")},
        {input = "00 00 00 00 00 ff", encoding = 0, output = Address.ether("00:00:00:00:00:ff")},
    }

    function tvbr_ether (tvbr, encoding)
        return tvbr:ether(), "ether()"
    end

    return true
        and run_test_cases_all_tests(tree, "ipv4", ipv4_test_cases, tvbr_ipv4, general_equality_test)
        and run_test_cases_all_tests(tree, "ipv6", ipv6_test_cases, tvbr_ipv6, general_equality_test)
        and run_test_cases_all_tests(tree, "ether", ether_test_cases, tvbr_ether, general_equality_test)
end

function time_tests(tree)

    local time_cases = {
        {input ="00 01 02 03", encoding = ENC_BIG_ENDIAN,    output = NSTime(0x00010203,0)},
        {input ="03 02 01 00", encoding = ENC_LITTLE_ENDIAN, output = NSTime(0x00010203,0)},
        {input ="00 01 02 03 04 05 06 07", encoding = ENC_BIG_ENDIAN,    output = NSTime(0x00010203, 0x04050607)},
        {input ="03 02 01 00 07 06 05 04", encoding = ENC_LITTLE_ENDIAN, output = NSTime(0x00010203, 0x04050607)},
    }

    local string_cases = {
        {input = "1994-11-05T13:15:30Z",      encoding = ENC_ISO_8601_DATE_TIME, output = NSTime(784041330, 0),
            hexlify=true},
        {input = "1994-11-05T13:15:30Z12345", encoding = ENC_ISO_8601_DATE_TIME, output = NSTime(784041330, 0),
            hexlify=true, variable_input_length = true, input_length = 20},
    }

    function tvbr_nstime(tvbr, encoding)
        if encoding == ENC_LITTLE_ENDIAN then
            return tvbr:le_nstime(), "le_nstime()"
        else
            return tvbr:nstime(encoding), string.format("nstime(%s)", format_encoding_for_print(encoding))
        end
    end

    return true
        and run_test_cases_all_tests(tree, "relative_time", time_cases, tvbr_nstime, general_equality_test)
        and run_test_cases_all_tests(tree, "absolute_time", time_cases, tvbr_nstime, general_equality_test)
        and run_test_cases_all_tests(tree, "absolute_time", string_cases, tvbr_nstime, general_equality_test)
end

function bytearray_tests(tree)

    local bytes_tests = {
        {input = "00 01 02 03 ff", encoding = 0, output = ByteArray.new("00 01 02 03 ff")}
    }

    function tvbr_bytes(tvbr, encoding)
        return tvbr:bytes(), "bytes()"
    end

    local varbytes_tests = {
        {input = "04 00 01 02 ff",          encoding = ENC_BIG_ENDIAN,
            output = ByteArray.new("00 01 02 ff"), fake_input_length = 1},
        {input = "00 04 00 01 02 ff",       encoding = ENC_BIG_ENDIAN,
            output = ByteArray.new("00 01 02 ff"), fake_input_length = 2},
        {input = "00 00 00 04 00 01 02 ff", encoding = ENC_BIG_ENDIAN,
            output = ByteArray.new("00 01 02 ff"), fake_input_length = 4},
    }

    return true
        and run_test_cases_all_tests(tree, "bytes", bytes_tests, tvbr_bytes, general_equality_test)
        and run_test_cases_all_tests(tree, "oid", bytes_tests, tvbr_bytes, general_equality_test)
        and run_test_cases_all_tests(tree, "rel_oid", bytes_tests, tvbr_bytes, general_equality_test)
        and run_test_cases_all_tests(tree, "system_id", bytes_tests, tvbr_bytes, general_equality_test)
        and run_test_cases_all_tests(tree, "uint_bytes", varbytes_tests, nil, general_equality_test)
end

function run_all_tests(tree)
    return true
        and simple_integer_tests(tree)
        and integer64_tests(tree)
        and string_tests(tree)
        and bool_char_tests(tree)
        and float_tests(tree)
        and address_tests(tree)
        and time_tests(tree)
        and bytearray_tests(tree)
end

local has_run = false
function myproto.dissector(tvb, pkt, root)
    if has_run then
        return
    end
    has_run = true
    local tree = root:add(myproto, tvb(0))
    if run_all_tests(tree) then
        print("All tests passed!")
        print()
    end
end

DissectorTable.get("udp.port"):add(65333, myproto)
