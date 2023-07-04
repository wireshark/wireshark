-- test script for various Lua functions
-- use with dhcp.pcap in test/captures directory

local testlib = require("testlib")

local FRAME = "frame"
local PER_FRAME = "per-frame"
local OTHER = "other"

-- expected number of runs per type
local n_frames = 4
local taptests = {
    [FRAME]=n_frames,
    [PER_FRAME]=n_frames*5,
    [OTHER]=44
}
testlib.init(taptests)

---------
-- the following are so we can use pcall (which needs a function to call)
local function setNSTime(nst,name,value)
    nst[name] = value
end

local function getNSTime(nst,name)
    local foo = nst[name]
end

------------- test script ------------
testlib.testing(OTHER,"negative tests")
testlib.test(OTHER,"NSTime.new-1",not pcall(NSTime,"FooBARhowdy"))
testlib.test(OTHER,"NSTime.new-2",not pcall(NSTime,"ip","FooBARhowdy"))
local tmptime = NSTime()
testlib.test(OTHER,"NSTime.set-3",pcall(setNSTime,tmptime,"secs",10))
testlib.test(OTHER,"NSTime.set-4",not pcall(setNSTime,tmptime,"foobar",1000))
testlib.test(OTHER,"NSTime.set-5",pcall(setNSTime,tmptime,"nsecs",123))
testlib.test(OTHER,"NSTime.set-6",not pcall(setNSTime,NSTime,"secs",0))
testlib.test(OTHER,"NSTime.set-7",not pcall(setNSTime,tmptime,"secs","foobar"))
testlib.test(OTHER,"NSTime.set-8",not pcall(setNSTime,NSTime,"nsecs",0))
testlib.test(OTHER,"NSTime.set-9",not pcall(setNSTime,tmptime,"nsecs","foobar"))

testlib.test(OTHER,"NSTime.get-10",pcall(getNSTime,tmptime,"secs"))
testlib.test(OTHER,"NSTime.get-11",pcall(getNSTime,tmptime,"nsecs"))
testlib.test(OTHER,"NSTime.get-12",not pcall(getNSTime,NSTime,"secs"))
testlib.test(OTHER,"NSTime.get-13",not pcall(getNSTime,NSTime,"nsecs"))


testlib.testing(OTHER,"basic tests")
local first = NSTime()
local second = NSTime(100,100)
local third = NSTime(0,100)
testlib.test(OTHER,"NSTime.secs-14", first.secs == 0)
testlib.test(OTHER,"NSTime.secs-15", second.secs == 100)
testlib.test(OTHER,"NSTime.secs-16", third.secs == 0)

testlib.test(OTHER,"NSTime.nsecs-17", first.nsecs == 0)
testlib.test(OTHER,"NSTime.nsecs-18", second.nsecs == 100)
testlib.test(OTHER,"NSTime.nsecs-19", third.nsecs == 100)

testlib.test(OTHER,"NSTime.eq-20", first == NSTime())
testlib.test(OTHER,"NSTime.neq-21", second ~= third)

testlib.test(OTHER,"NSTime.add-22", first + second == second)
testlib.test(OTHER,"NSTime.add-23", third + NSTime(100,0) == second)
testlib.test(OTHER,"NSTime.add-24", NSTime(100) + NSTime(nil,100) == second)

testlib.test(OTHER,"NSTime.lt-25", third < second)
testlib.test(OTHER,"NSTime.gt-26", third > first)
testlib.test(OTHER,"NSTime.le-27", second <= NSTime(100,100))

testlib.test(OTHER,"NSTime.unm-28", -first == first)
testlib.test(OTHER,"NSTime.unm-29", -(-second) == second)
testlib.test(OTHER,"NSTime.unm-30", -second == NSTime(-100,-100))
testlib.test(OTHER,"NSTime.unm-31", -third == NSTime(0,-100))

testlib.test(OTHER,"NSTime.tostring-32", tostring(first) == "0.000000000")
testlib.test(OTHER,"NSTime.tostring-33", tostring(second) == "100.000000100")
testlib.test(OTHER,"NSTime.tostring-34", tostring(third) == "0.000000100")

testlib.test(OTHER,"NSTime.tonumber-35", first:tonumber() == 0.0)
testlib.test(OTHER,"NSTime.tonumber-36", second:tonumber() == 100.0000001)
testlib.test(OTHER,"NSTime.tonumber-37", third:tonumber() == 0.0000001)

testlib.testing(OTHER,"setters/getters")
first.secs = 123
first.nsecs = 100
testlib.test(OTHER,"NSTime.set-38", first == NSTime(123,100))
testlib.test(OTHER,"NSTime.get-39", first.secs == 123)
testlib.test(OTHER,"NSTime.get-40", first.nsecs == 100)

local minus0_4 = NSTime() - NSTime(0,400000000)
testlib.test(OTHER,"NSTime.negative_tonumber-41", minus0_4:tonumber() == -0.4)
testlib.test(OTHER,"NSTime.negative_tostring-42", tostring(minus0_4) == "-0.400000000")
local minus0_4 = NSTime() - NSTime(1,400000000)
testlib.test(OTHER,"NSTime.negative_tonumber-43", minus0_4:tonumber() == -1.4)
testlib.test(OTHER,"NSTime.negative_tostring-44", tostring(minus0_4) == "-1.400000000")


----------------------------------

-- declare some field extractors
local f_frame_time       = Field.new("frame.time")
local f_frame_time_rel   = Field.new("frame.time_relative")
local f_frame_time_delta = Field.new("frame.time_delta")

local tap = Listener.new()

local begin = NSTime()
local now, previous

function tap.packet(pinfo,tvb,frame)
    testlib.countPacket(FRAME)
    testlib.testing(FRAME,"NSTime in Frame")

    local fi_now = f_frame_time()
    local fi_rel = f_frame_time_rel()
    local fi_delta = f_frame_time_delta()

    testlib.test(PER_FRAME,"typeof-1", typeof(begin) == "NSTime")
    testlib.test(PER_FRAME,"typeof-2", typeof(fi_now()) == "NSTime")

    now = fi_now()
    if testlib.getPktCount(FRAME) == 1 then
        testlib.test(PER_FRAME,"__eq-1", begin == fi_delta())
        testlib.test(PER_FRAME,"NSTime.secs-1", fi_delta().secs == 0)
        testlib.test(PER_FRAME,"NSTime.nsecs-1", fi_delta().nsecs == 0)
        begin = fi_now()
    else
        testlib.test(PER_FRAME,"__sub__eq-1", now - previous == fi_delta())
        testlib.test(PER_FRAME,"__sub__eq-2", now - begin == fi_rel())
        testlib.test(PER_FRAME,"__add-1", (previous - begin) + (now - previous) == fi_rel())
    end
    previous = now

    testlib.pass(FRAME)
end

function tap.draw()
    testlib.getResults()
end
