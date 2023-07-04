----------------------------------------
-- This just verifies the number of args it got is what it expected.
-- The first arg should be a number, for how many total args to expect,
-- including itself.

local testlib = require("testlib")

local ARGS = "args"
testlib.init({ [ARGS]=3 })

-----------------------------

testlib.testing("Command-line args")

local arg={...} -- get passed-in args

testlib.test(ARGS, "arg1", arg ~= nil and #arg > 0)

local numargs = tonumber(arg[1])
testlib.test(ARGS, "arg2", numargs ~= nil)

testlib.test(ARGS, "arg3", #arg == numargs)

testlib.getResults()
