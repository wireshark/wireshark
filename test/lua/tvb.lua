----------------------------------------
-- script-name: tvb.lua
-- This tests the Tvb/TvbRange and proto_add_XXX_item API.
----------------------------------------

------------- general test helper funcs ------------
local FRAME = "frame"
local OTHER = "other"

local total_tests = 0
local function getTotal()
    return total_tests
end


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
    total_tests = total_tests + 1
end

local fail_count = 0
local function setFailed(name)
    fail_count = fail_count + 1
    total_tests = total_tests + 1
end

-- expected number of runs per type
--
-- CHANGE THIS TO MATCH HOW MANY TESTS THERE ARE
--
local taptests = { [FRAME]=4, [OTHER]=247 }

local function getResults()
    print("\n-----------------------------\n")
    for k,v in pairs(taptests) do
        -- each frame run executes the same test again, so multiply by #frames
        if k ~= "frame" and v ~= 0 then v = (v * taptests.frame) end

        if v ~= 0 and passed[k] ~= v then
            print("Something didn't run or ran too much... tests failed!")
            print("Dissector type " .. k ..
                  " expected: " .. v ..
                  " (" .. ( v / taptests.frame) .. ")" ..
                  ", but got: " .. tostring(passed[k]) ..
                  " (" .. (tonumber(passed[k] or 0) / taptests.frame) .. ")" )
            return false
        end
    end
    print("All tests passed!\n\n")
    return true
end


local function testing(type,...)
    print("\n-------- Testing " .. tostring(...) ..
          " ---- for packet # " .. getPktCount(type) ..
          " --------\n")
end

local function execute(type,name, ...)
    io.stdout:write("test --> "..name.."-"..getTotal().."-"..getPktCount(type).."...")
    local results = { ... }
    if #results > 0 and results[1] == true then
        setPassed(type)
        io.stdout:write("passed\n")
        return true
    else
        setFailed(type)
        io.stdout:write("failed!\n")
        if #results > 1 then
            print("Got the following error: '" .. tostring(results[2]) .. "'")
        end
        error(name.." test failed!")
    end
end

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

----------------------------------
-- modify original test function for now, kinda sorta
local orig_execute = execute
execute = function (...)
    return orig_execute(OTHER,...)
end

----------------------------------------
-- creates a Proto object for our testing
local test_proto = Proto("test","Test Protocol")

local numinits = 0
function test_proto.init()
    numinits = numinits + 1
    if numinits == 2 then
        getResults()
    end
end


----------------------------------------
-- a table of all of our Protocol's fields and test input and expected output
local testfield =
{
    basic =
    {
        STRING  = ProtoField.string ("test.basic.string",  "Basic string"),
        BOOLEAN = ProtoField.bool   ("test.basic.boolean", "Basic boolean", 16, {"yes","no"}, 0x0001),
        UINT16  = ProtoField.uint16 ("test.basic.uint16",  "Basic uint16")
    },

    time =
    {
        ABSOLUTE_LOCAL = ProtoField.absolute_time("test.time.absolute.local","Time absolute local"),
        ABSOLUTE_UTC   = ProtoField.absolute_time("test.time.absolute.utc",  "Time absolute utc", 1001),
    },

}

-- create a flat array table of the above that can be registered
local pfields = {}
for _,t in pairs(testfield) do
    for k,v in pairs(t) do
        pfields[#pfields+1] = v
    end
end

-- register them
test_proto.fields = pfields

print("test_proto ProtoFields registered")


local getfield =
{
    basic =
    {
        STRING  = Field.new ("test.basic.string"),
        BOOLEAN = Field.new ("test.basic.boolean"),
        UINT16  = Field.new ("test.basic.uint16")
    },

    time =
    {
        ABSOLUTE_LOCAL = Field.new ("test.time.absolute.local"),
        ABSOLUTE_UTC   = Field.new ("test.time.absolute.utc"),
    },

}

local function addMatchFields(match_fields, ... )
    match_fields[#match_fields + 1] = { ... }
end

local function getFieldInfos(name)
    local base, field = name:match("([^.]+)%.(.+)")
    if not base or not field then
        error("failed to get base.field from '" .. name .. "'")
    end
    local t = { getfield[base][field]() }
    return t
end

local function verifyFields(name, match_fields)
    local finfos = getFieldInfos(name)

    execute ("verify-fields-size-" .. name, #finfos == #match_fields,
             "#finfos=" .. #finfos .. ", #match_fields=" .. #match_fields)

    for i, t in ipairs(match_fields) do
        if type(t) ~= 'table' then
            error("verifyFields didn't get a table inside the matches table")
        end
        if #t ~= 1 then
            error("verifyFields matches table's table is not size 1")
        end
        local result = finfos[i]()
        local value  = t[1]
        print(
                name .. " got:",
                "\n\tfinfos [" .. i .. "]='" .. tostring( result ) .. "'",
                "\n\tmatches[" .. i .. "]='" .. tostring( value  ) .. "'"
             )
        execute ( "verify-fields-value-" .. name .. "-" .. i, result == value )
    end
end


local function addMatchValues(match_values, ... )
    match_values[#match_values + 1] = { ... }
end

local function addMatchFieldValues(match_fields, match_values, match_both, ...)
    addMatchFields(match_fields, match_both)
    addMatchValues(match_values, match_both, ...)
end

local result_values = {}
local function resetResults()
    result_values = {}
end

local function treeAddPField(...)
    local t = { pcall ( TreeItem.add_packet_field, ... ) }
    if t[1] == nil then
        return nil, t[2]
    end
    -- it gives back a TreeItem, then the results
    if typeof(t[2]) ~= 'TreeItem' then
        return nil, "did not get a TreeItem returned from TreeItem.add_packet_field, "..
                    "got a '" .. typeof(t[2]) .."'"
    end

    if #t ~= 4 then
        return nil, "did not get 3 return values from TreeItem.add_packet_field"
    end

    result_values[#result_values + 1] = { t[3], t[4] }

    return true
end

local function verifyResults(name, match_values)
    execute ("verify-results-size-" .. name, #result_values == #match_values,
             "#result_values=" .. #result_values ..
             ", #match_values=" .. #match_values)

    for j, t in ipairs(match_values) do
        if type(t) ~= 'table' then
            error("verifyResults didn't get a table inside the matches table")
        end
        for i, match in ipairs(t) do
            local r = result_values[j][i]
            print(
                    name .. " got:",
                    "\n\tresults[" .. j .. "][" .. i .. "]='" .. tostring( r ) .. "'",
                    "\n\tmatches[" .. j .. "][" .. i .. "]='" .. tostring( match ) .. "'"
                 )
            local result_type, match_type
            if type(match) == 'userdata' then
                match_type = typeof(match)
            else
                match_type = type(match)
            end
            if type(r) == 'userdata' then
                result_type = typeof(r)
            else
                result_type = type(r)
            end
            execute ( "verify-results-type-" .. name .. "-" .. i, result_type == match_type )
            execute ( "verify-results-value-" .. name .. "-" .. i, r == match )
        end
    end
end

-- Compute the difference in seconds between local time and UTC
-- from http://lua-users.org/wiki/TimeZone
local function get_timezone()
  local now = os.time()
  return os.difftime(now, os.time(os.date("!*t", now)))
end
local timezone = get_timezone()
print ("timezone = " .. timezone)

----------------------------------------
-- The following creates the callback function for the dissector.
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
function test_proto.dissector(tvbuf,pktinfo,root)

    incPktCount(FRAME)
    incPktCount(OTHER)

    testing(OTHER, "Basic")

    local tree = root:add(test_proto, tvbuf:range(0,tvbuf:len()))

    -- create a fake Tvb to use for testing
    local teststring = "this is the string for the first test"
    local bytearray = ByteArray.new(teststring, true)
    local tvb = bytearray:tvb("Basic")

    local function callTreeAdd(tree,...)
        tree:add(...)
    end

    local string_match_fields = {}

    execute ("basic-string", tree:add(testfield.basic.STRING, tvb:range(0,tvb:len())) ~= nil )
    addMatchFields(string_match_fields, teststring)

    execute ("basic-string", pcall (callTreeAdd, tree, testfield.basic.STRING, tvb:range() ) )
    addMatchFields(string_match_fields, teststring)

    verifyFields("basic.STRING", string_match_fields)

    tvb = ByteArray.new("00FF 0001 8000"):tvb("Basic")
    local bool_match_fields = {}

    execute ("basic-boolean", pcall (callTreeAdd, tree, testfield.basic.BOOLEAN, tvb:range(0,2)) )
    addMatchFields(bool_match_fields, true)

    execute ("basic-boolean", pcall (callTreeAdd, tree, testfield.basic.BOOLEAN, tvb:range(2,2)) )
    addMatchFields(bool_match_fields, true)

    execute ("basic-boolean", pcall (callTreeAdd, tree, testfield.basic.BOOLEAN, tvb:range(4,2)) )
    addMatchFields(bool_match_fields, false)

    verifyFields("basic.BOOLEAN", bool_match_fields )

    local uint16_match_fields = {}

    execute ("basic-uint16", pcall (callTreeAdd, tree, testfield.basic.UINT16, tvb:range(0,2)) )
    addMatchFields(uint16_match_fields, 255)

    execute ("basic-uint16", pcall (callTreeAdd, tree, testfield.basic.UINT16, tvb:range(2,2)) )
    addMatchFields(uint16_match_fields, 1)

    execute ("basic-uint16", pcall (callTreeAdd, tree, testfield.basic.UINT16, tvb:range(4,2)) )
    addMatchFields(uint16_match_fields, 32768)

    verifyFields("basic.UINT16", uint16_match_fields)

    local function callTreeAddLE(tree,...)
        tree:add_le(...)
    end

    execute ("basic-uint16-le", pcall (callTreeAddLE, tree, testfield.basic.UINT16, tvb:range(0,2)) )
    addMatchFields(uint16_match_fields, 65280)

    execute ("basic-uint16-le", pcall (callTreeAddLE, tree, testfield.basic.UINT16, tvb:range(2,2)) )
    addMatchFields(uint16_match_fields, 256)

    execute ("basic-uint16-le", pcall (callTreeAddLE, tree, testfield.basic.UINT16, tvb:range(4,2)) )
    addMatchFields(uint16_match_fields, 128)

    verifyFields("basic.UINT16", uint16_match_fields)


----------------------------------------
    testing(OTHER, "tree:add Time")

    tvb = ByteArray.new("00000000 00000000 0000FF0F 00FF000F"):tvb("Time")
    local ALOCAL = testfield.time.ABSOLUTE_LOCAL
    local alocal_match_fields = {}

    execute ("time-local",    pcall (callTreeAdd,   tree, ALOCAL, tvb:range(0,8)) )
    addMatchFields(alocal_match_fields, NSTime())

    execute ("time-local",    pcall (callTreeAdd,   tree, ALOCAL, tvb:range(8,8)) )
    addMatchFields(alocal_match_fields, NSTime( 0x0000FF0F, 0x00FF000F) )

    execute ("time-local-le", pcall (callTreeAddLE, tree, ALOCAL, tvb:range(0,8)) )
    addMatchFields(alocal_match_fields, NSTime())

    execute ("time-local-le", pcall (callTreeAddLE, tree, ALOCAL, tvb:range(8,8)) )
    addMatchFields(alocal_match_fields, NSTime( 0x0FFF0000, 0x0F00FF00 ) )

    verifyFields("time.ABSOLUTE_LOCAL", alocal_match_fields)

    local AUTC = testfield.time.ABSOLUTE_UTC
    local autc_match_fields = {}

    execute ("time-utc",    pcall (callTreeAdd,   tree, AUTC, tvb:range(0,8)) )
    addMatchFields(autc_match_fields, NSTime())

    execute ("time-utc",    pcall (callTreeAdd,   tree, AUTC, tvb:range(8,8)) )
    addMatchFields(autc_match_fields, NSTime( 0x0000FF0F, 0x00FF000F) )

    execute ("time-utc-le", pcall (callTreeAddLE, tree, AUTC, tvb:range(0,8)) )
    addMatchFields(autc_match_fields, NSTime())

    execute ("time-utc-le", pcall (callTreeAddLE, tree, AUTC, tvb:range(8,8)) )
    addMatchFields(autc_match_fields, NSTime( 0x0FFF0000, 0x0F00FF00 ) )

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields )

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time bytes")

    resetResults()
    local autc_match_values = {}

    -- something to make this easier to read
    local function addMatch(...)
        addMatchFieldValues(autc_match_fields, autc_match_values, ...)
    end

    -- tree:add_packet_field(ALOCAL, tvb:range(0,8), ENC_BIG_ENDIAN)
    execute ("add_pfield-time-bytes-local",    treeAddPField ( tree, AUTC, tvb:range(0,8), ENC_BIG_ENDIAN) )
    addMatch( NSTime(), 8)

    execute ("add_pfield-time-bytes-local",    treeAddPField ( tree, AUTC, tvb:range(8,8), ENC_BIG_ENDIAN) )
    addMatch( NSTime( 0x0000FF0F, 0x00FF000F), 8)

    execute ("add_pfield-time-bytes-local-le", treeAddPField ( tree, AUTC, tvb:range(0,8), ENC_LITTLE_ENDIAN) )
    addMatch( NSTime(), 8)

    execute ("add_pfield-time-bytes-local-le", treeAddPField ( tree, AUTC, tvb:range(8,8), ENC_LITTLE_ENDIAN) )
    addMatch( NSTime( 0x0FFF0000, 0x0F00FF00 ), 8)

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-time-bytes-local", autc_match_values)

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time string ENC_ISO_8601_DATE_TIME")

    resetResults()
    autc_match_values = {}

    local datetimestring1 =   "2013-03-01T22:14:48+00:00" -- this is 1362176088 seconds epoch time
    local tvb1 = ByteArray.new(datetimestring1, true):tvb("Date_Time string 1")
    local datetimestring2 = "  2013-03-01T17:14:48+05:00" -- this is 1362176088 seconds epoch time
    local tvb2 = ByteArray.new(datetimestring2 .. "  foobar", true):tvb("Date_Time string 2")
    local datetimestring3 = "  2013-03-01T16:44+05:30"    -- this is 1362176040 seconds epoch time
    local tvb3 = ByteArray.new(datetimestring3, true):tvb("Date_Time string 3")
    local datetimestring4 =   "2013-03-02T01:44:00-03:30" -- this is 1362176040 seconds epoch time
    local tvb4 = ByteArray.new(datetimestring4, true):tvb("Date_Time string 4")
    local datetimestring5 =   "2013-03-01T22:14:48Z"      -- this is 1362176088 seconds epoch time
    local tvb5 = ByteArray.new(datetimestring5, true):tvb("Date_Time string 5")
    local datetimestring6 =   "2013-03-01T22:14Z"         -- this is 1362176040 seconds epoch time
    local tvb6 = ByteArray.new(datetimestring6, true):tvb("Date_Time string 6")

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb1:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176088, 0), string.len(datetimestring1))

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb2:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176088, 0), string.len(datetimestring2))

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb3:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176040, 0), string.len(datetimestring3))

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb4:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176040, 0), string.len(datetimestring4))

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb5:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176088, 0), string.len(datetimestring5))

    execute ("add_pfield-datetime-local", treeAddPField ( tree, AUTC, tvb6:range(), ENC_ISO_8601_DATE_TIME) )
    addMatch( NSTime( 1362176040, 0), string.len(datetimestring6))

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-datetime-local", autc_match_values)

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time string ENC_ISO_8601_DATE")

    resetResults()
    autc_match_values = {}

    local datestring1 =   "2013-03-01"  -- this is 1362096000 seconds epoch time
    local d_tvb1 = ByteArray.new(datestring1, true):tvb("Date string 1")
    local datestring2 = "  2013-03-01"  -- this is 1362096000 seconds epoch time
    local d_tvb2 = ByteArray.new(datestring2 .. "  foobar", true):tvb("Date string 2")

    execute ("add_pfield-date-local", treeAddPField ( tree, AUTC, d_tvb1:range(), ENC_ISO_8601_DATE) )
    addMatch( NSTime( 1362096000, 0), string.len(datestring1))

    execute ("add_pfield-date-local", treeAddPField ( tree, AUTC, d_tvb2:range(), ENC_ISO_8601_DATE) )
    addMatch( NSTime( 1362096000, 0), string.len(datestring2))

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-date-local", autc_match_values)

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time string ENC_ISO_8601_TIME")

    resetResults()
    autc_match_values = {}

    local timestring1 =   "22:14:48"  -- this is 80088 seconds
    local t_tvb1 = ByteArray.new(timestring1, true):tvb("Time string 1")
    local timestring2 = "  22:14:48"  -- this is 80088 seconds
    local t_tvb2 = ByteArray.new(timestring2 .. "  foobar", true):tvb("Time string 2")

    local now = os.date("!*t")
    now.hour = 22
    now.min  = 14
    now.sec  = 48
    local timebase = os.time( now )
    timebase = timebase + timezone
    print ("timebase = " .. tostring(timebase) .. ", timezone=" .. timezone)

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, t_tvb1:range(), ENC_ISO_8601_TIME) )
    addMatch( NSTime( timebase, 0), string.len(timestring1))

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, t_tvb2:range(), ENC_ISO_8601_TIME) )
    addMatch( NSTime( timebase, 0), string.len(timestring2))

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-time-local", autc_match_values)

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time string ENC_RFC_822")

    resetResults()
    autc_match_values = {}

    local rfc822string1 =   "Fri, 01 Mar 13 22:14:48 GMT"  -- this is 1362176088 seconds epoch time
    local rfc822_tvb1 = ByteArray.new(rfc822string1, true):tvb("RFC 822 Time string 1")
    local rfc822string2 = "  Fri, 01 Mar 13 22:14:48 GMT"  -- this is 1362176088 seconds epoch time
    local rfc822_tvb2 = ByteArray.new(rfc822string2 .. "  foobar", true):tvb("RFC 822 Time string 2")

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, rfc822_tvb1:range(), ENC_RFC_822) )
    addMatch( NSTime( 1362176088, 0), string.len(rfc822string1))

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, rfc822_tvb2:range(), ENC_RFC_822) )
    addMatch( NSTime( 1362176088, 0), string.len(rfc822string2))

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-rfc822-local", autc_match_values)

----------------------------------------
    testing(OTHER, "tree:add_packet_field Time string ENC_RFC_1123")

    resetResults()
    autc_match_values = {}

    local rfc1123string1 =   "Fri, 01 Mar 2013 22:14:48 GMT"  -- this is 1362176088 seconds epoch time
    local rfc1123_tvb1 = ByteArray.new(rfc1123string1, true):tvb("RFC 1123 Time string 1")
    local rfc1123string2 = "  Fri, 01 Mar 2013 22:14:48 GMT"  -- this is 1362176088 seconds epoch time
    local rfc1123_tvb2 = ByteArray.new(rfc1123string2 .. "  foobar", true):tvb("RFC 1123 Time string 2")

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, rfc1123_tvb1:range(), ENC_RFC_1123) )
    addMatch( NSTime( 1362176088, 0), string.len(rfc1123string1))

    execute ("add_pfield-time-local", treeAddPField ( tree, AUTC, rfc1123_tvb2:range(), ENC_RFC_1123) )
    addMatch( NSTime( 1362176088, 0), string.len(rfc1123string2))

    verifyFields("time.ABSOLUTE_UTC", autc_match_fields)

    verifyResults("add_pfield-rfc1123-local", autc_match_values)

----------------------------------------

    setPassed(FRAME)
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific UDP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("udp.port"):add(65333, test_proto)
DissectorTable.get("udp.port"):add(65346, test_proto)

print("test_proto dissector registered")
