-- test script for ByteArray integer functions

local testlib = require("testlib")

local INT = "int"
local UINT = "uint"
local INT64 = "int64"
local UINT64 = "uint64"
local LE_INT = "le_int"
local LE_UINT = "le_uint"
local LE_INT64 = "le_int64"
local LE_UINT64 = "le_uint64"

-- expected number of runs per type
local taptests = {
    [INT]=14,
    [UINT]=14,
    [INT64]=15,
    [UINT64]=15,
    [LE_INT]=14,
    [LE_UINT]=14,
    [LE_INT64]=15,
    [LE_UINT64]=15
}
testlib.init(taptests)

local empty = ByteArray.new("")
local be_data = ByteArray.new("FF 00 00 00 00 00 00 00")
local le_data = ByteArray.new("00 00 00 00 00 00 00 FF")

-- the following are so we can use pcall (which needs a function to call)

local function ByteArray_int(array,offset,length)
    local value = array:int(offset,length)
end

local function ByteArray_uint(array,offset,length)
    local value = array:uint(offset,length)
end

local function ByteArray_int64(array,offset,length)
    local value = array:int64(offset,length)
end

local function ByteArray_uint64(array,offset,length)
    local value = array:uint64(offset,length)
end

local function ByteArray_le_int(array,offset,length)
    local value = array:le_int(offset,length)
end

local function ByteArray_le_uint(array,offset,length)
    local value = array:le_uint(offset,length)
end

local function ByteArray_le_int64(array,offset,length)
    local value = array:le_int64(offset,length)
end

local function ByteArray_le_uint64(array,offset,length)
    local value = array:le_uint64(offset,length)
end

------------- test script ------------

testlib.testing(INT,"negative tests")
testlib.test(INT,"ByteArray:int-0",not pcall(ByteArray_int, empty))
testlib.test(INT,"ByteArray:int-1",not pcall(ByteArray_int, be_data))
testlib.test(INT,"ByteArray:int-2",not pcall(ByteArray_int, be_data, -1))
testlib.test(INT,"ByteArray:int-3",not pcall(ByteArray_int, be_data, 0))
testlib.test(INT,"ByteArray:int-4",not pcall(ByteArray_int, be_data, 0, -1))
testlib.test(INT,"ByteArray:int-5",not pcall(ByteArray_int, be_data, 0, 0))
testlib.test(INT,"ByteArray:int-6",not pcall(ByteArray_int, be_data, 0, 5))
testlib.test(INT,"ByteArray:int-7",not pcall(ByteArray_int, be_data, 7, 2))
testlib.test(INT,"ByteArray:int-8",not pcall(ByteArray_int, be_data, 8, 1))

testlib.testing(INT,"positive tests")
testlib.test(INT,"ByteArray:int-9", be_data:int(0, 1) == -1)
testlib.test(INT,"ByteArray:int-10", be_data:int(0, 2) == -256)
testlib.test(INT,"ByteArray:int-11", be_data:int(0, 3) == -65536)
testlib.test(INT,"ByteArray:int-12", be_data:int(0, 4) == -16777216)
testlib.test(INT,"ByteArray:int-13", be_data:subset(2, 2):int() == 0)

testlib.testing(UINT,"negative tests")
testlib.test(UINT,"ByteArray:uint-0",not pcall(ByteArray_uint, empty))
testlib.test(UINT,"ByteArray:uint-1",not pcall(ByteArray_uint, be_data))
testlib.test(UINT,"ByteArray:uint-2",not pcall(ByteArray_uint, be_data, -1))
testlib.test(UINT,"ByteArray:uint-3",not pcall(ByteArray_uint, be_data, 0))
testlib.test(UINT,"ByteArray:uint-4",not pcall(ByteArray_uint, be_data, 0, -1))
testlib.test(UINT,"ByteArray:uint-5",not pcall(ByteArray_uint, be_data, 0, 0))
testlib.test(UINT,"ByteArray:uint-6",not pcall(ByteArray_uint, be_data, 0, 5))
testlib.test(UINT,"ByteArray:uint-7",not pcall(ByteArray_uint, be_data, 7, 2))
testlib.test(UINT,"ByteArray:uint-8",not pcall(ByteArray_uint, be_data, 8, 1))

testlib.testing(UINT,"positive tests")
testlib.test(UINT,"ByteArray:uint-9", be_data:uint(0, 1) == 255)
testlib.test(UINT,"ByteArray:uint-10", be_data:uint(0, 2) == 65280)
testlib.test(UINT,"ByteArray:uint-11", be_data:uint(0, 3) == 16711680)
testlib.test(UINT,"ByteArray:uint-12", be_data:uint(0, 4) == 4278190080)
testlib.test(UINT,"ByteArray:uint-13", be_data:subset(2, 2):uint() == 0)

testlib.testing(INT64,"negative tests")
testlib.test(INT64,"ByteArray:int64-0",not pcall(ByteArray_int64, empty))
testlib.test(INT64,"ByteArray:int64-1",not pcall(ByteArray_int64, be_data, -1))
testlib.test(INT64,"ByteArray:int64-2",not pcall(ByteArray_int64, be_data, 0, 0))
testlib.test(INT64,"ByteArray:int64-3",not pcall(ByteArray_int64, be_data, 0, 9))
testlib.test(INT64,"ByteArray:int64-4",not pcall(ByteArray_int64, be_data, 7, 2))
testlib.test(INT64,"ByteArray:int64-5",not pcall(ByteArray_int64, be_data, 8, 1))

testlib.testing(INT64,"positive tests")
testlib.test(INT64,"ByteArray:int64-6", be_data:int64(0, 1):tonumber() == -1)
testlib.test(INT64,"ByteArray:int64-7", be_data:int64(0, 2):tonumber() == -256)
testlib.test(INT64,"ByteArray:int64-8", be_data:int64(0, 3):tonumber() == -65536)
testlib.test(INT64,"ByteArray:int64-9", be_data:int64(0, 4):tonumber() == -16777216)
testlib.test(INT64,"ByteArray:int64-10", be_data:int64(0, 5):tonumber() == -4294967296)
testlib.test(INT64,"ByteArray:int64-11", be_data:int64(0, 6):tonumber() == -1099511627776)
testlib.test(INT64,"ByteArray:int64-12", be_data:int64(0, 7):tonumber() == -281474976710656)
testlib.test(INT64,"ByteArray:int64-13", be_data:int64():tonumber() == -72057594037927936)
testlib.test(INT64,"ByteArray:int64-14", be_data:subset(2, 2):int64():tonumber() == 0)

testlib.testing(UINT64,"negative tests")
testlib.test(UINT64,"ByteArray:uint64-0",not pcall(ByteArray_uint64, empty))
testlib.test(UINT64,"ByteArray:uint64-1",not pcall(ByteArray_uint64, be_data, -1))
testlib.test(UINT64,"ByteArray:uint64-2",not pcall(ByteArray_uint64, be_data, 0, 0))
testlib.test(UINT64,"ByteArray:uint64-3",not pcall(ByteArray_uint64, be_data, 0, 9))
testlib.test(UINT64,"ByteArray:uint64-4",not pcall(ByteArray_uint64, be_data, 7, 2))
testlib.test(UINT64,"ByteArray:uint64-5",not pcall(ByteArray_uint64, be_data, 8, 1))

testlib.testing(UINT64,"positive tests")
testlib.test(UINT64,"ByteArray:uint64-6", be_data:uint64(0, 1):tonumber() == 255)
testlib.test(UINT64,"ByteArray:uint64-7", be_data:uint64(0, 2):tonumber() == 65280)
testlib.test(UINT64,"ByteArray:uint64-8", be_data:uint64(0, 3):tonumber() == 16711680)
testlib.test(UINT64,"ByteArray:uint64-9", be_data:uint64(0, 4):tonumber() == 4278190080)
testlib.test(UINT64,"ByteArray:uint64-10", be_data:uint64(0, 5):tonumber() == 1095216660480)
testlib.test(UINT64,"ByteArray:uint64-11", be_data:uint64(0, 6):tonumber() == 280375465082880)
testlib.test(UINT64,"ByteArray:uint64-12", be_data:uint64(0, 7):tonumber() == 71776119061217280)
testlib.test(UINT64,"ByteArray:uint64-13", be_data:uint64():tonumber() == 18374686479671623680)
testlib.test(UINT64,"ByteArray:uint64-14", be_data:subset(2, 2):uint64():tonumber() == 0)

testlib.testing(LE_INT,"negative tests")
testlib.test(LE_INT,"ByteArray:le_int-0",not pcall(ByteArray_le_int, empty))
testlib.test(LE_INT,"ByteArray:le_int-1",not pcall(ByteArray_le_int, le_data))
testlib.test(LE_INT,"ByteArray:le_int-2",not pcall(ByteArray_le_int, le_data, -1))
testlib.test(LE_INT,"ByteArray:le_int-3",not pcall(ByteArray_le_int, le_data, 0))
testlib.test(LE_INT,"ByteArray:le_int-4",not pcall(ByteArray_le_int, le_data, 0, -1))
testlib.test(LE_INT,"ByteArray:le_int-5",not pcall(ByteArray_le_int, le_data, 0, 0))
testlib.test(LE_INT,"ByteArray:le_int-6",not pcall(ByteArray_le_int, le_data, 0, 5))
testlib.test(LE_INT,"ByteArray:le_int-7",not pcall(ByteArray_le_int, le_data, 7, 2))
testlib.test(LE_INT,"ByteArray:le_int-8",not pcall(ByteArray_le_int, le_data, 8, 1))

testlib.testing(LE_INT,"positive tests")
testlib.test(LE_INT,"ByteArray:le_int-9", le_data:le_int(7) == -1)
testlib.test(LE_INT,"ByteArray:le_int-10", le_data:le_int(6, 2) == -256)
testlib.test(LE_INT,"ByteArray:le_int-11", le_data:le_int(5, 3) == -65536)
testlib.test(LE_INT,"ByteArray:le_int-12", le_data:le_int(4, 4) == -16777216)
testlib.test(LE_INT,"ByteArray:le_int-13", be_data:subset(2, 2):le_int() == 0)

testlib.testing(LE_UINT,"negative tests")
testlib.test(LE_UINT,"ByteArray:le_uint-0",not pcall(ByteArray_le_uint, empty))
testlib.test(LE_UINT,"ByteArray:le_uint-1",not pcall(ByteArray_le_uint, le_data))
testlib.test(LE_UINT,"ByteArray:le_uint-2",not pcall(ByteArray_le_uint, le_data, -1))
testlib.test(LE_UINT,"ByteArray:le_uint-3",not pcall(ByteArray_le_uint, le_data, 0))
testlib.test(LE_UINT,"ByteArray:le_uint-4",not pcall(ByteArray_le_uint, le_data, 0, -1))
testlib.test(LE_UINT,"ByteArray:le_uint-5",not pcall(ByteArray_le_uint, le_data, 0, 0))
testlib.test(LE_UINT,"ByteArray:le_uint-6",not pcall(ByteArray_le_uint, le_data, 0, 5))
testlib.test(LE_UINT,"ByteArray:le_uint-7",not pcall(ByteArray_le_uint, le_data, 7, 2))
testlib.test(LE_UINT,"ByteArray:le_uint-8",not pcall(ByteArray_le_uint, le_data, 8, 1))

testlib.testing(LE_UINT,"positive tests")
testlib.test(LE_UINT,"ByteArray:le_uint-9", le_data:le_uint(7) == 255)
testlib.test(LE_UINT,"ByteArray:le_uint-10", le_data:le_uint(6, 2) == 65280)
testlib.test(LE_UINT,"ByteArray:le_uint-11", le_data:le_uint(5, 3) == 16711680)
testlib.test(LE_UINT,"ByteArray:le_uint-12", le_data:le_uint(4, 4) == 4278190080)
testlib.test(LE_UINT,"ByteArray:le_uint-13", be_data:subset(2, 2):le_uint() == 0)

testlib.testing(LE_INT64,"negative tests")
testlib.test(LE_INT64,"ByteArray:le_int64-0",not pcall(ByteArray_le_int64, empty))
testlib.test(LE_INT64,"ByteArray:le_int64-1",not pcall(ByteArray_le_int64, le_data, -1))
testlib.test(LE_INT64,"ByteArray:le_int64-2",not pcall(ByteArray_le_int64, le_data, 0, 0))
testlib.test(LE_INT64,"ByteArray:le_int64-3",not pcall(ByteArray_le_int64, le_data, 0, 9))
testlib.test(LE_INT64,"ByteArray:le_int64-4",not pcall(ByteArray_le_int64, le_data, 7, 2))
testlib.test(LE_INT64,"ByteArray:le_int64-5",not pcall(ByteArray_le_int64, le_data, 8, 1))

testlib.testing(LE_INT64,"positive tests")
testlib.test(LE_INT64,"ByteArray:le_int64-6", le_data:le_int64(7):tonumber() == -1)
testlib.test(LE_INT64,"ByteArray:le_int64-7", le_data:le_int64(6, 2):tonumber() == -256)
testlib.test(LE_INT64,"ByteArray:le_int64-8", le_data:le_int64(5, 3):tonumber() == -65536)
testlib.test(LE_INT64,"ByteArray:le_int64-9", le_data:le_int64(4, 4):tonumber() == -16777216)
testlib.test(LE_INT64,"ByteArray:le_int64-10", le_data:le_int64(3, 5):tonumber() == -4294967296)
testlib.test(LE_INT64,"ByteArray:le_int64-11", le_data:le_int64(2, 6):tonumber() == -1099511627776)
testlib.test(LE_INT64,"ByteArray:le_int64-12", le_data:le_int64(1, 7):tonumber() == -281474976710656)
testlib.test(LE_INT64,"ByteArray:le_int64-13", le_data:le_int64():tonumber() == -72057594037927936)
testlib.test(LE_INT64,"ByteArray:le_int64-14", le_data:subset(0, 2):le_int64():tonumber() == 0)

testlib.testing(LE_UINT64,"negative tests")
testlib.test(LE_UINT64,"ByteArray:le_uint64-0",not pcall(ByteArray_le_uint64, empty))
testlib.test(LE_UINT64,"ByteArray:le_uint64-1",not pcall(ByteArray_le_uint64, le_data, -1))
testlib.test(LE_UINT64,"ByteArray:le_uint64-2",not pcall(ByteArray_le_uint64, le_data, 0, 0))
testlib.test(LE_UINT64,"ByteArray:le_uint64-3",not pcall(ByteArray_le_uint64, le_data, 0, 9))
testlib.test(LE_UINT64,"ByteArray:le_uint64-4",not pcall(ByteArray_le_uint64, le_data, 7, 2))
testlib.test(LE_UINT64,"ByteArray:le_uint64-5",not pcall(ByteArray_le_uint64, le_data, 8, 1))

testlib.testing(LE_UINT64,"positive tests")
testlib.test(LE_UINT64,"ByteArray:le_uint64-6", le_data:le_uint64(7):tonumber() == 255)
testlib.test(LE_UINT64,"ByteArray:le_uint64-7", le_data:le_uint64(6, 2):tonumber() == 65280)
testlib.test(LE_UINT64,"ByteArray:le_uint64-8", le_data:le_uint64(5, 3):tonumber() == 16711680)
testlib.test(LE_UINT64,"ByteArray:le_uint64-9", le_data:le_uint64(4, 4):tonumber() == 4278190080)
testlib.test(LE_UINT64,"ByteArray:le_uint64-10", le_data:le_uint64(3, 5):tonumber() == 1095216660480)
testlib.test(LE_UINT64,"ByteArray:le_uint64-11", le_data:le_uint64(2, 6):tonumber() == 280375465082880)
testlib.test(LE_UINT64,"ByteArray:le_uint64-12", le_data:le_uint64(1, 7):tonumber() == 71776119061217280)
testlib.test(LE_UINT64,"ByteArray:le_uint64-13", le_data:le_uint64():tonumber() == 18374686479671623680)
testlib.test(LE_UINT64,"ByteArray:le_uint64-14", le_data:subset(0, 2):le_uint64():tonumber() == 0)

testlib.getResults()