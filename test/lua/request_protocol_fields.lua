-- test script for request_protocol_fields

local testlib = require("testlib")

local OTHER = "other"

testlib.init({
    [OTHER] = 8,
})

--------------------------

testlib.testing(OTHER, "request_protocol_fields")

local ok, result = pcall(request_protocol_fields, "frame")
testlib.test(OTHER, "request_protocol_fields-string-0", ok)
testlib.test(OTHER, "request_protocol_fields-string-1", type(result) == "table")
testlib.test(OTHER, "request_protocol_fields-string-2", result[1] == "frame" and #result == 1)

local ok_invalid, result_invalid = pcall(request_protocol_fields, "no_such_proto")
testlib.test(OTHER, "request_protocol_fields-invalid-0", ok_invalid)
testlib.test(OTHER, "request_protocol_fields-invalid-1", #result_invalid == 0)

local ok_table, result_table = pcall(request_protocol_fields, {"frame", "ip", "no_such_proto"})
testlib.test(OTHER, "request_protocol_fields-table-0", ok_table)
testlib.test(OTHER, "request_protocol_fields-table-1", #result_table == 2 and result_table[1] == "frame" and result_table[2] == "ip")

local ok_bad = pcall(request_protocol_fields, {"frame", 1})
testlib.test(OTHER, "request_protocol_fields-table-2", not ok_bad)

--------------------------

testlib.getResults()
