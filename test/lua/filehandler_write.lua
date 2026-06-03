-- filehandler_write.lua
-- Tests CaptureInfoConst attributes in a write-only FileHandler.

local testlib = require("testlib")
local CC = "captureconst"

testlib.init({ [CC] = 7 })

local fh = FileHandler.new(
    "FileHandler write test",
    "fh_write_test",
    "Tests CaptureInfoConst attribute accessibility from a write FileHandler",
    "ws"
)

function fh.can_write_encap(encap)
    return true
end

function fh.write_open(file, capture)
    testlib.testing(CC, "CaptureInfoConst attributes")

    testlib.test(CC, "encap",           type(capture.encap)            == "number")
    testlib.test(CC, "type",            type(capture.type)             == "number")
    testlib.test(CC, "snapshot_length", type(capture.snapshot_length)  == "number")

    -- comment/hardware/os/user_app read from wdh->shb_hdrs; value may be nil
    local ok1 = pcall(function() return capture.comment  end)
    testlib.test(CC, "comment",  ok1)

    local ok2 = pcall(function() return capture.hardware end)
    testlib.test(CC, "hardware", ok2)

    local ok3 = pcall(function() return capture.os       end)
    testlib.test(CC, "os",       ok3)

    local ok4 = pcall(function() return capture.user_app end)
    testlib.test(CC, "user_app", ok4)

    testlib.getResults()
    return true
end

function fh.write(file, capture, frame)
    return true
end

register_filehandler(fh)
