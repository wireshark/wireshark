-- test script for various Lua functions
-- use with dhcp.pcap in test/captures directory


------------- general test helper funcs ------------
local FRAME = "frame"
local OTHER = "other"

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
end

-- expected number of runs per type
-- note ip only runs 3 times because it gets removed
-- and bootp only runs twice because the filter makes it run
-- once and then it gets replaced with a different one for the second time
local taptests = { [FRAME]=4, [OTHER]=37 }
local function getResults()
    print("\n-----------------------------\n")
    for k,v in pairs(taptests) do
        if passed[k] ~= v then
            print("Something didn't run or ran too much... tests failed!")
            print("Listener type "..k.." expected: "..v..", but got: "..tostring(passed[k]))
            return false
        end
    end
    print("All tests passed!\n\n")
    return true
end


local function testing(type,...)
    print("---- Testing "..type.." ---- "..tostring(...).." for packet # "..getPktCount(type).."----")
end

local function test(type,name, ...)
    io.stdout:write("test "..type.."-->"..name.."-"..getPktCount(type).."...")
    if (...) == true then
        io.stdout:write("passed\n")
        return true
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

---------
-- the following are so we can use pcall (which needs a function to call)
local function makeNSTime(...)
    local foo = NSTime(...)
end

local function setNSTime(nst,name,value)
    nst[name] = value
end

local function getNSTime(nst,name)
    local foo = nst[name]
end

------------- test script ------------
testing(OTHER,"negative tests")
local orig_test = test
test = function (...)
    if orig_test(OTHER,...) then
        setPassed(OTHER)
    end
end
test("NSTime.new-1",not pcall(makeNSTime,"FooBARhowdy"))
test("NSTime.new-2",not pcall(makeNSTime,"ip","FooBARhowdy"))
local tmptime = NSTime()
test("NSTime.set-3",pcall(setNSTime,tmptime,"secs",10))
test("NSTime.set-4",not pcall(setNSTime,tmptime,"foobar",1000))
test("NSTime.set-5",pcall(setNSTime,tmptime,"nsecs",123))
test("NSTime.set-6",not pcall(setNSTime,NSTime,"secs",0))
test("NSTime.set-7",not pcall(setNSTime,tmptime,"secs","foobar"))
test("NSTime.set-8",not pcall(setNSTime,NSTime,"nsecs",0))
test("NSTime.set-9",not pcall(setNSTime,tmptime,"nsecs","foobar"))

test("NSTime.get-10",pcall(getNSTime,tmptime,"secs"))
test("NSTime.get-11",pcall(getNSTime,tmptime,"nsecs"))
test("NSTime.get-12",not pcall(getNSTime,NSTime,"secs"))
test("NSTime.get-13",not pcall(getNSTime,NSTime,"nsecs"))


testing(OTHER,"basic tests")
local first = NSTime()
local second = NSTime(100,100)
local third = NSTime(0,100)
test("NSTime.secs-14", first.secs == 0)
test("NSTime.secs-15", second.secs == 100)
test("NSTime.secs-16", third.secs == 0)

test("NSTime.nsecs-17", first.nsecs == 0)
test("NSTime.nsecs-18", second.nsecs == 100)
test("NSTime.nsecs-19", third.nsecs == 100)

test("NSTime.eq-20", first == NSTime())
test("NSTime.neq-21", second ~= third)

test("NSTime.add-22", first + second == second)
test("NSTime.add-23", third + NSTime(100,0) == second)
test("NSTime.add-24", NSTime(100) + NSTime(nil,100) == second)

test("NSTime.lt-25", third < second)
test("NSTime.gt-26", third > first)
test("NSTime.le-27", second <= NSTime(100,100))

test("NSTime.unm-28", -first == first)
test("NSTime.unm-29", -(-second) == second)
test("NSTime.unm-30", -second == NSTime(-100,-100))
test("NSTime.unm-31", -third == NSTime(0,-100))

test("NSTime.tostring-32", tostring(first) == "0.000000000")
test("NSTime.tostring-33", tostring(second) == "100.000000100")
test("NSTime.tostring-34", tostring(third) == "0.000000100")


testing(OTHER,"setters/getters")
first.secs = 123
first.nsecs = 100
test("NSTime.set-35", first == NSTime(123,100))
test("NSTime.get-36", first.secs == 123)
test("NSTime.get-37", first.nsecs == 100)


----------------------------------
-- revert to original test function, kinda sorta
test = function (...)
    return orig_test(FRAME,...)
end


-- declare some field extractors
local f_frame_time       = Field.new("frame.time")
local f_frame_time_rel   = Field.new("frame.time_relative")
local f_frame_time_delta = Field.new("frame.time_delta")

local tap = Listener.new()

local begin = NSTime()
local now, previous

function tap.packet(pinfo,tvb,frame)
    incPktCount(FRAME)
    testing(FRAME,"NSTime in Frame")

    local fi_now = f_frame_time()
    local fi_rel = f_frame_time_rel()
    local fi_delta = f_frame_time_delta()

    test("typeof-1", typeof(begin) == "NSTime")
    test("typeof-2", typeof(fi_now()) == "NSTime")

    now = fi_now()
    if getPktCount(FRAME) == 1 then
        test("__eq-1", begin == fi_delta())
        test("NSTime.secs-1", fi_delta().secs == 0)
        test("NSTime.nsecs-1", fi_delta().nsecs == 0)
        begin = fi_now()
    else
        test("__sub__eq-1", now - previous == fi_delta())
        test("__sub__eq-2", now - begin == fi_rel())
        test("__add-1", (previous - begin) + (now - previous) == fi_rel())
    end
    previous = now

    setPassed(FRAME)
end

function tap.draw()
    getResults()
end
