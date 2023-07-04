----------------------------------------
-- library name: testlib.lua
--
-- Provides common functions for other lua test scripts to use.
----------------------------------------
--[[
    This library aims to codify the most common practices used in testing
    Wireshark's lua features. The intent is to reduce boilerplate code
    so test scripts can focus on test cases.

    Tests are nominally classified into named groups.
    (In practice, most test files just use a single group called "other",
    but this should be tidied up at some point.)
    A test script must call testlib.init() with a table of
    group names and the number of tests expected to be run in each group.
    This number can be zero if you want to declare a group but don't
    need to check that a specific number of tests is run.

    Suggested use (abridged):

        local testlib = require("testlib")
        testlib.init({ other = 3 })
        testlib.testing("other", "example tests")
        testlib.test("other", "firsttest", 1+1 == 2)
        testlib.test("other", "funccall", pcall(my_function, func_args), "function should succeed")
        testlib.test("other", "funccall", not pcall(my_function2, func_args), "function expected to give error")
        testlib.getResults()

    For information on specific functions, keep reading.
--]]

----------------------------------------
-- This is the module object, which will be returned at the end of this file.
local M = {
    ["groups"] = {},
}

----------------------------------------
-- Initialize the test suite. Define one or more testing groups,
-- giving the expected number of tests to run for each.
-- (Telling it to "expect" zero tests for a group just skips
-- the check that a specific number of tests ran in that group.)
-- May be called repeatedly if you want to define group names
-- at runtime.
M.init = function(t)
    for group, expected in pairs(t) do
        M.groups[group] = {
            ["expected"] = expected,
            ["passed"] = 0,
            ["failed"] = 0,
            ["total"] = 0,
            ["packets"] = 0,
        }
    end
end

----------------------------------------
-- Indicate a passed test in the named group.
M.pass = function(group)
    M.groups[group].passed = M.groups[group].passed + 1
    M.groups[group].total = M.groups[group].total + 1
end

----------------------------------------
-- Indicate a failed test in the named group.
M.fail = function(group)
    M.groups[group].failed = M.groups[group].failed + 1
    M.groups[group].total = M.groups[group].total + 1
end

----------------------------------------
-- There are some tests which track the number of packets they're testing.
-- Use this function to count a single packet as being "seen" by a group.
M.countPacket = function(group)
    M.groups[group].packets = M.groups[group].packets + 1
end

----------------------------------------
-- Get the number of packets that have been counted under the named group.
M.getPktCount = function(group)
    return M.groups[group].packets
end

----------------------------------------
-- Print a banner reporting test progress.
-- Has no material affect on test progression, but is useful for
-- understanding the test results.
M.testing = function(group, msg)
    if msg == nil then
        msg, group = group, nil
    end
    if group then
        if M.groups[group].packets > 0 then
            print(string.format("\n-------- Testing %s -- %s for packet # %d --------\n",
                group, msg, M.groups[group].packets))
        else
            print(string.format("\n-------- Testing %s -- %s --------\n",
                group, msg))
        end
    else
        print(string.format("\n-------- Testing %s --------\n", msg))
    end
end

----------------------------------------
-- Core function: test a condition, report and track its status.
-- The output format shown here is what was commonly used in test scripts,
-- but can be changed.
M.test = function(group, name, cond, msg)
    -- io.stdout:write() doesn't add a newline like print() does
    io.stdout:write(string.format("test %s --> %s-%d-%d...",
            group, name, M.groups[group].total, M.groups[group].packets))
    if cond then
        io.stdout:write("passed\n")
        M.pass(group)
        return true
    else
        io.stdout:write("failed!\n")
        M.fail(group)
        if msg then
            print(string.format("Got the following error: '%s'", msg))
        end
        -- Using error() causes the entire test script to abort.
        -- This is how the lua test suite typically operates.
        -- If a test script wants to continue with subsequent tests
        -- after a failed test, this behaviour could be made
        -- configurable in this module.
        error(name .. " test failed!")
        return false
    end
end

----------------------------------------
-- Call this at the finale of a test script to output the results of testing.
-- This is where the number of tests run is compared to what was expected,
-- if applicable.
-- Scripts which run over empty.pcap will usually call this at the end of
-- the file.
-- Scripts which test by creating a protocol object will call this from
-- the object's .init() method *the second time it is called*.
-- Others usually call it in a tap listener's .draw() method,
-- which tshark calls once when it reaches the end of the pcap.
M.getResults = function()
    local rv = true
    print("\n===== Test Results =====")
    for group, num in pairs(M.groups) do
        if num.expected > 0 and num.total ~= num.expected then
            rv = false
            print("Something didn't run or ran too much... tests failed!")
            print(string.format("%s: expected %d tests but ran %d tests",
                    group, num.expected, num.total))
        end
        if num.failed > 0 then
            rv = false
            print(string.format("%s: passed %d/%d, FAILED %d/%d",
                    group, num.passed, num.total, num.failed, num.total))
        else
            print(string.format("%s: passed %d/%d",
                    group, num.passed, num.total))
        end
    end
    if rv then
        -- The python wrapper which performs our lua testing
        -- expects to see this string in the output if there were no failures.
        print("All tests passed!")
    else
        print("Some tests failed!")
    end
    return rv
end

----------------------------------------
-- That's the end of this library. Return the module we've created.
return M
