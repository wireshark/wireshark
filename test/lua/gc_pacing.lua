----------------------------------------
-- script-name: gc_pacing.lua
-- Test that the garbage collector keeps up with short-lived objects that
-- have finalizers (__gc metamethods). In incremental mode, if most of the
-- garbage has finalizers, the heap grows with the number of objects
-- created, without bound.
--
-- The first argument is "generational" if Wireshark is expected to use
-- generational mode with this version of Lua.
----------------------------------------

local testlib = require("testlib")

local FIN = "finalizers"

testlib.init({ [FIN] = 2 })

local args = { ... }
local generational = args[1] == "generational"

-- Returns the current garbage collection mode.
local function gc_mode()
    -- Lua 5.3 does not have generational mode, or this option.
    local ok, mode = pcall(collectgarbage, "incremental")
    if not ok then
        return "incremental"
    end
    collectgarbage(mode)
    return mode
end

-- Calls fn, which creates garbage, n times, and returns the peak growth
-- of the Lua heap, in KB.
local function peak_heap(n, fn)
    collectgarbage("collect")
    local base = collectgarbage("count")
    local peak = 0
    for _ = 1, n do
        fn()
        local growth = collectgarbage("count") - base
        if growth > peak then
            peak = growth
        end
    end
    return peak
end

-----------------------------

testlib.testing(FIN, "Tables with finalizers")

if generational then
    local gcmt = { __gc = function() end }
    -- In incremental mode this grows to about 50-80 MB.
    local peak = peak_heap(20000, function()
        for _ = 1, 100 do
            setmetatable({}, gcmt)
        end
    end)
    testlib.test(FIN, string.format("peak heap growth %.0f KB", peak), peak < 16 * 1024)
    testlib.test(FIN, "generational mode", gc_mode() == "generational")
else
    print("Skipping tests that require generational mode")
    testlib.test(FIN, "peak heap growth (skipped)", true)
    testlib.test(FIN, "generational mode (skipped)", true)
end

testlib.getResults()
