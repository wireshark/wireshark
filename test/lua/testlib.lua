----------------------------------------
-- library name: testlib.lua
--
-- Provides common functions for other lua test scripts to use.
----------------------------------------

local M = {
    ["groups"] = {},
}

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

-- Indicate a passed test in the named group
M.pass = function(group)
    M.groups[group].passed = M.groups[group].passed + 1
    M.groups[group].total = M.groups[group].total + 1
end

-- Indicate a failed test in the named group
M.fail = function(group)
    M.groups[group].failed = M.groups[group].failed + 1
    M.groups[group].total = M.groups[group].total + 1
end

-- Increment the number of packets tracked under the named group
M.countPacket = function(group)
    M.groups[group].packets = M.groups[group].packets + 1
end

-- Get the number of packets tracked under the named group
M.getPktCount = function(group)
    return M.groups[group].packets
end

-- Print a banner reporting test progress
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

-- Test a condition, report and track its status
M.test = function(group, name, cond, msg)
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
        error(name .. " test failed!")
    end
end

-- Print the results of testing
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
        -- expects to see this string in the output if there were no failures
        print("All tests passed!")
    end
    return rv
end

return M
