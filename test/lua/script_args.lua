----------------------------------------
-- This just verifies the number of args it got is what it expected.
-- The first arg should be a number, for how many total args to expect,
-- including itself.

local function testing(...)
    print("---- Testing "..tostring(...).." ----")
end

local function test(name, result)
    io.stdout:write("test "..name.."...")
    if result == true then
        io.stdout:write("passed\n")
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

-----------------------------

testing("Command-line args")

local arg={...} -- get passed-in args

test("arg1", arg ~= nil and #arg > 0)

local numargs = tonumber(arg[1])
test("arg2", numargs ~= nil)

test("arg3", #arg == numargs)

print("\n-----------------------------\n")

print("All tests passed!\n\n")

