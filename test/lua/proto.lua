----------------------------------------
-- script-name: proto.lua
-- Test the Proto/ProtoField API
----------------------------------------

------------- general test helper funcs ------------
local testlib = require("testlib")

local OTHER = "other"

-- expected number of runs per type
-- # of fields test doesn't work on Lua 5.4
local taptests = {
    [OTHER]=47
}
testlib.init(taptests)

---------
-- the following are so we can use pcall (which needs a function to call)
local function callFunc(func,...)
    func(...)
end

local function callObjFuncGetter(vart,varn,tobj,name,...)
    vart[varn] = tobj[name](...)
end

local function setValue(tobj,name,value)
    tobj[name] = value
end

local function getValue(tobj,name)
    local foo = tobj[name]
end

------------- test script ------------

----------------------------------------
-- creates a Proto object, but doesn't register it yet
testlib.testing(OTHER,"Proto creation")

testlib.test(OTHER,"Proto.__call", pcall(callFunc,Proto,"foo","Foo Protocol"))
testlib.test(OTHER,"Proto.__call", pcall(callFunc,Proto,"foo1","Foo1 Protocol"))
testlib.test(OTHER,"Proto.__call", not pcall(callFunc,Proto,"","Bar Protocol"))
testlib.test(OTHER,"Proto.__call", not pcall(callFunc,Proto,nil,"Bar Protocol"))
testlib.test(OTHER,"Proto.__call", not pcall(callFunc,Proto,"bar",""))
testlib.test(OTHER,"Proto.__call", not pcall(callFunc,Proto,"bar",nil))


local dns = Proto("mydns","MyDNS Protocol")

testlib.test(OTHER,"Proto.__tostring", tostring(dns) == "Proto: MYDNS")

----------------------------------------
-- multiple ways to do the same thing: create a protocol field (but not register it yet)
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
testlib.testing(OTHER,"ProtoField creation")

local pfields = {} -- a table to hold fields, so we can pass them back/forth through pcall()
--- variable                -- what dissector.lua did, so we almost match it
local pf_trasaction_id     = 1 -- ProtoField.new("Transaction ID", "mydns.trans_id", ftypes.UINT16)
local pf_flags             = 2 -- ProtoField.new("Flags", "mydns.flags", ftypes.UINT16, nil, base.HEX)
local pf_num_questions     = 3 -- ProtoField.uint16("mydns.num_questions", "Number of Questions")
local pf_num_answers       = 4 -- ProtoField.uint16("mydns.num_answers", "Number of Answer RRs")
local pf_num_authority_rr  = 5 -- ProtoField.uint16("mydns.num_authority_rr", "Number of Authority RRs")
local pf_num_additional_rr = 6 -- ProtoField.uint16("mydns.num_additional_rr", "Number of Additional RRs")

testlib.test(OTHER,"ProtoField.new",pcall(callObjFuncGetter, pfields,pf_trasaction_id, ProtoField,"new", "Transaction ID", "mydns.trans_id", ftypes.INT16,nil,"base.DEC"))
testlib.test(OTHER,"ProtoField.new",pcall(callObjFuncGetter, pfields,pf_flags, ProtoField,"new", "Flags", "mydns.flags", ftypes.UINT16, nil, "base.HEX"))

-- tries to register a field that already exists (from the real dns proto dissector) but with incompatible type
testlib.test(OTHER,"ProtoField.new_duplicate_bad",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "Flags", "dns.flags", ftypes.INT16, nil, "base.HEX"))
testlib.test(OTHER,"ProtoField.int16_duplicate_bad",not pcall(callObjFuncGetter, pfields,10, ProtoField,"int16", "dns.id","Transaction ID"))
-- now compatible (but different type)
testlib.test(OTHER,"ProtoField.new_duplicate_ok",pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "Flags", "dns.flags", ftypes.UINT32, nil, "base.HEX"))
testlib.test(OTHER,"ProtoField.uint16_duplicate_ok",pcall(callObjFuncGetter, pfields,10, ProtoField,"uint16", "dns.id","Transaction ID"))

-- invalid valuestring arg
testlib.test(OTHER,"ProtoField.new_invalid_valuestring",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "Transaction ID", "mydns.trans_id", ftypes.INT16,"howdy","base.DEC"))
-- invalid ftype
testlib.test(OTHER,"ProtoField.new_invalid_ftype",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "Transaction ID", "mydns.trans_id", 9999))
-- invalid description
--testlib.test(OTHER,"ProtoField.new_invalid_description",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "", "mydns.trans_id", ftypes.INT16))
testlib.test(OTHER,"ProtoField.new_invalid_description",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", nil, "mydns.trans_id", ftypes.INT16))

testlib.test(OTHER,"ProtoField.new_invalid_abbr",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "trans id", "", ftypes.INT16))
testlib.test(OTHER,"ProtoField.new_invalid_abbr",not pcall(callObjFuncGetter, pfields,10, ProtoField,"new", "trans id", nil, ftypes.INT16))

testlib.test(OTHER,"ProtoField.int16",pcall(callObjFuncGetter, pfields,pf_num_questions, ProtoField,"int16", "mydns.num_questions", "Number of Questions"))
testlib.test(OTHER,"ProtoField.int16",pcall(callObjFuncGetter, pfields,pf_num_answers, ProtoField,"int16", "mydns.num_answers", "Number of Answer RRs",base.DEC))
testlib.test(OTHER,"ProtoField.int16",pcall(callObjFuncGetter, pfields,pf_num_authority_rr, ProtoField,"int16", "mydns.num_authority_rr", "Number of Authority RRs",base.DEC))
testlib.test(OTHER,"ProtoField.int16",pcall(callObjFuncGetter, pfields,pf_num_additional_rr, ProtoField,"int16", "mydns.num_additional_rr", "Number of Additional RRs"))

-- now undo the table thingy
pf_trasaction_id = pfields[pf_trasaction_id]
pf_flags = pfields[pf_flags]
pf_num_questions = pfields[pf_num_questions]
pf_num_answers = pfields[pf_num_answers]
pf_num_authority_rr = pfields[pf_num_authority_rr]
pf_num_additional_rr = pfields[pf_num_additional_rr]

-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
-- again the following shows different ways of doing the same thing basically
local pf_flag_response              = ProtoField.new("Response", "mydns.flags.response", ftypes.BOOLEAN, {"this is a response","this is a query"}, 16, 0x8000, "is the message a response?")
local pf_flag_opcode                = ProtoField.new("Opcode", "mydns.flags.opcode", ftypes.UINT16, nil, base.DEC, 0x7800, "operation code")
local pf_flag_authoritative         = ProtoField.new("Authoritative", "mydns.flags.authoritative", ftypes.BOOLEAN, nil, 16, 0x0400, "is the response authoritative?")
local pf_flag_truncated             = ProtoField.bool("mydns.flags.truncated", "Truncated", 16, nil, 0x0200, "is the message truncated?")
local pf_flag_recursion_desired     = ProtoField.bool("mydns.flags.recursion_desired", "Recursion desired", 16, {"yes","no"}, 0x0100, "do the query recursivley?")
local pf_flag_recursion_available   = ProtoField.bool("mydns.flags.recursion_available", "Recursion available", 16, nil, 0x0080, "does the server support recursion?")
local pf_flag_z                     = ProtoField.uint16("mydns.flags.z", "World War Z - Reserved for future use", base.HEX, nil, 0x0040, "when is it the future?")
local pf_flag_authenticated         = ProtoField.bool("mydns.flags.authenticated", "Authenticated", 16, {"yes","no"}, 0x0020, "did the server DNSSEC authenticate?")
local pf_flag_checking_disabled     = ProtoField.bool("mydns.flags.checking_disabled", "Checking disabled", 16, nil, 0x0010)

-- no, these aren't all the DNS response codes - this is just an example
local rcodes = {
        [0] = "No Error",
        [1] = "Format Error",
        [2] = "Server Failure",
        [3] = "Non-Existent Domain",
        [9] = "Server Not Authoritative for zone"
}
-- the above rcodes table is used in this next ProtoField
local pf_flag_rcode         = ProtoField.uint16("mydns.flags.rcode", "Response code", base.DEC, rcodes, 0x000F)
local pf_query              = ProtoField.new("Query", "mydns.query", ftypes.BYTES)
local pf_query_name         = ProtoField.new("Name", "mydns.query.name", ftypes.STRING)
local pf_query_name_len     = ProtoField.new("Name Length", "mydns.query.name.len", ftypes.UINT8)
local pf_query_label_count  = ProtoField.new("Label Count", "mydns.query.label.count", ftypes.UINT8)
local rrtypes = { [1] = "A (IPv4 host address)", [2] = "NS (authoritative name server)", [28] = "AAAA (for geeks only)" }
local pf_query_type         = ProtoField.uint16("mydns.query.type", "Type", base.DEC, rrtypes)
-- again, not all class types are listed here
local classes = {
        [0] = "Reserved",
        [1] = "IN (Internet)",
        [2] = "The 1%",
        [5] = "First class",
        [6] = "Business class",
        [65535] = "Cattle class"
}
local pf_query_class        = ProtoField.uint16("mydns.query.class", "Class", base.DEC, classes, nil, "keep it classy folks")


testlib.testing(OTHER,"Proto functions")

----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programaticaly
-- and then set dns.fields to it, so as to avoid forgetting a field
local myfields = { pf_trasaction_id, pf_flags,
    pf_num_questions, pf_num_answers, pf_num_authority_rr, pf_num_additional_rr,
    pf_flag_response, pf_flag_opcode, pf_flag_authoritative,
    pf_flag_truncated, pf_flag_recursion_desired, pf_flag_recursion_available,
    pf_flag_z, pf_flag_authenticated, pf_flag_checking_disabled, pf_flag_rcode,
    pf_query, pf_query_name, pf_query_name_len, pf_query_label_count, pf_query_type, pf_query_class }

--dns.fields = myfields
testlib.test(OTHER,"Proto.fields-set", pcall(setValue,dns,"fields",myfields))
testlib.test(OTHER,"Proto.fields-get", pcall(getValue,dns,"fields"))
-- This test doesn't work on Lua 5.4 because the # operator includes the
-- reference(s) that are the linked list of allocated and free keys,
-- starting with LUA_RIDX_LAST + 1 == 3.
-- testlib.test(OTHER,"Proto.fields-get", #dns.fields == #myfields)

local pf_foo = ProtoField.uint16("myfoo.com", "Fooishly", base.DEC, rcodes, 0x000F)

local foo = Proto("myfoo","MyFOO Protocol")
local bar = Proto("mybar","MyBAR Protocol")

testlib.test(OTHER,"Proto.fields-set", pcall(setValue,foo,"fields",pf_foo))
testlib.test(OTHER,"Proto.fields-get", #foo.fields == 1)
testlib.test(OTHER,"Proto.fields-get", foo.fields[1] == pf_foo)

testlib.test(OTHER,"Proto.fields-set", not pcall(setValue,bar,"fields","howdy"))
testlib.test(OTHER,"Proto.fields-set", not pcall(setValue,bar,"fields",nil))
testlib.test(OTHER,"Proto.fields-get", #bar.fields == 0)

testlib.test(OTHER,"Proto.name-get", foo.name == "MYFOO")
testlib.test(OTHER,"Proto.name-set", not pcall(setValue,foo,"name","howdy"))

testlib.test(OTHER,"Proto.description-get", foo.description == "MyFOO Protocol")
testlib.test(OTHER,"Proto.description-set", not pcall(setValue,foo,"description","howdy"))

testlib.test(OTHER,"Proto.prefs-get", typeof(foo.prefs) == "Prefs")
testlib.test(OTHER,"Proto.prefs-set", not pcall(setValue,foo,"prefs","howdy"))

local function dummy()
    setFailed(OTHER)
    error("dummy function called!")
    return
end

-- can't get this because we haven't set it yet
testlib.test(OTHER,"Proto.dissector-get", not pcall(getValue,foo,"dissector"))
-- now set it
testlib.test(OTHER,"Proto.dissector-set", pcall(setValue,foo,"dissector",dummy))
testlib.test(OTHER,"Proto.dissector-set", not pcall(setValue,foo,"dissector","howdy"))
testlib.test(OTHER,"Proto.dissector-get", pcall(getValue,foo,"dissector"))

testlib.test(OTHER,"Proto.prefs_changed-set", pcall(setValue,foo,"prefs_changed",dummy))
testlib.test(OTHER,"Proto.prefs_changed-get", not pcall(getValue,foo,"prefs_changed"))
testlib.test(OTHER,"Proto.prefs_changed-set", not pcall(setValue,foo,"prefs_changed","howdy"))

local function dummy_init()
    testlib.test(OTHER,"Proto.init-called",true)
end

testlib.test(OTHER,"Proto.init-set", pcall(setValue,foo,"init",dummy_init))
testlib.test(OTHER,"Proto.init-set", pcall(setValue,bar,"init",dummy_init))

testlib.test(OTHER,"Proto.init-get", not pcall(getValue,foo,"init"))
testlib.test(OTHER,"Proto.init-set", not pcall(setValue,foo,"init","howdy"))

testlib.getResults()

