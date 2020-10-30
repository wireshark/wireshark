-- test script for wslua utility functions


------------- helper funcs ------------
local function testing(...)
    print("---- Testing "..tostring(...).." ----")
end

local function test(name, ...)
    io.stdout:write("test "..name.."...")
    if (...) == true then
        io.stdout:write("passed\n")
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

--------------------------

-- Note: This tests expects some specific default values
testing("get_preference")

success = pcall(get_preference)
test("get_preference-empty-0", not success)
test("get_preference-empty-1",get_preference("") == nil)
test("get_preference-unknown-0",get_preference("g") == nil)
test("get_preference-unknown-1",get_preference("gui") == nil)
test("get_preference-unknown-2",get_preference("gui.") == nil)
test("get_preference-unknown-3",get_preference("gui.ask") == nil)
test("get_preference-unknown-4",get_preference("ugi.ask_unsaved") == nil)
test("get_preference-uint-0",get_preference("gui.fileopen.preview") == 3)
test("get_preference-bool-0",get_preference("gui.ask_unsaved") == true)
test("get_preference-bool-1",get_preference("gui.interfaces_show_hidden") == false)
test("get_preference-enum-1",get_preference("gui.console_open") == "NEVER")
test("get_preference-string-0",get_preference("gui.window_title") == "")
test("get_preference-range-0",get_preference("http.tls.port") == "443")
success = pcall(get_preference, "user_dlt.encaps_table")
test("get_preference-uat-0", not success)

--------------------------

testing("set_preference")

success = pcall(set_preference)
test("set_preference-empty-0", not success)
test("set_preference-empty-1",set_preference("") == nil)
test("set_preference-unknown-0",set_preference("g") == nil)
test("set_preference-unknown-1",set_preference("gui") == nil)
test("set_preference-unknown-2",set_preference("gui.") == nil)
test("set_preference-unknown-3",set_preference("gui.ask") == nil)
test("set_preference-unknown-4",set_preference("ugi.ask_unsaved") == nil)
success = pcall(set_preference,"gui.fileopen.preview")
test("set_preference-uint-0", not success)
success = pcall(set_preference,"gui.fileopen.preview",true)
test("set_preference-uint-1", not success)
success = pcall(set_preference,"gui.fileopen.preview","string")
test("set_preference-uint-2", not success)
test("set_preference-uint-3",set_preference("gui.fileopen.preview",3) == false)
test("set_preference-uint-4",set_preference("gui.fileopen.preview",42) == true)
test("set_preference-uint-4-get",get_preference("gui.fileopen.preview") == 42)
success = pcall(set_preference,"gui.ask_unsaved")
test("set_preference-bool-0", not success)
success = pcall(set_preference,"gui.ask_unsaved",42)
test("set_preference-bool-1", not success)
success = pcall(set_preference,"gui.ask_unsaved","string")
test("set_preference-bool-2", not success)
test("set_preference-bool-3",set_preference("gui.ask_unsaved", true) == false)
test("set_preference-bool-4",set_preference("gui.ask_unsaved", false) == true)
success = pcall(set_preference,"gui.console_open")
test("set_preference-enum-0", not success)
success = pcall(set_preference,"gui.console_open",true)
test("set_preference-enum-1", not success)
test("set_preference-enum-2",set_preference("gui.console_open","NEVER") == false)
test("set_preference-enum-3",set_preference("gui.console_open","AUTOMATIC") == true)
test("set_preference-enum-3-get",get_preference("gui.console_open") == "AUTOMATIC")
test("set_preference-enum-4",set_preference("gui.console_open","ALWAYS") == true)
test("set_preference-enum-5",set_preference("gui.console_open","unknown") == false)
test("set_preference-enum-6",set_preference("gui.console_open",42) == false)
success = pcall(set_preference,"gui.window_title")
test("set_preference-string-0", not success)
success = pcall(set_preference,"gui.window_title",true)
test("set_preference-string-1", not success)
test("set_preference-string-2",set_preference("gui.window_title","Title") == true)
test("set_preference-string-2-get",get_preference("gui.window_title") == "Title")
test("set_preference-string-3",set_preference("gui.window_title","Title") == false)
test("set_preference-string-4",set_preference("gui.window_title","") == true)
test("set_preference-string-4-get",get_preference("gui.window_title") == "")
test("set_preference-string-5",set_preference("gui.window_title","") == false)
success = pcall(set_preference,"http.tls.port")
test("set_preference-range-0", not success)
success = pcall(set_preference,"http.tls.port","65536") -- Number too big
test("set_preference-range-1", not success)
success = pcall(set_preference,"http.tls.port","http") -- Syntax error
test("set_preference-range-2", not success)
test("set_preference-range-3",set_preference("http.tls.port","443") == false)
test("set_preference-range-4",set_preference("http.tls.port","443-444") == true)
test("set_preference-range-4-get",get_preference("http.tls.port") == "443-444")
test("set_preference-range-5",set_preference("http.tls.port","443-444") == false)
success = pcall(set_preference, "user_dlt.encaps_table")
test("set_preference-uat-0", not success)

--------------------------

testing("reset_preference")

success = pcall(set_preference)
test("reset_preference-empty-0", not success)
test("reset_preference-empty-1",reset_preference("") == nil)
test("reset_preference-unknown-0",reset_preference("unknown") == nil)
test("reset_preference-uint-0",reset_preference("gui.fileopen.preview") == true)
test("reset_preference-uint-0-get",get_preference("gui.fileopen.preview") == 3)
test("reset_preference-bool-0",reset_preference("gui.ask_unsaved") == true)
test("reset_preference-bool-0-get",get_preference("gui.ask_unsaved") == true)
test("reset_preference-enum-0",reset_preference("gui.console_open") == true)
test("reset_preference-enum-0-get",get_preference("gui.console_open") == "NEVER")
test("reset_preference-string-0",reset_preference("gui.window_title") == true)
test("reset_preference-string-0-get",get_preference("gui.window_title") == "")
test("reset_preference-range-0",reset_preference("http.tls.port") == true)
test("reset_preference-range-0-get",get_preference("http.tls.port") == "443")

print("\n-----------------------------\n")
print("All tests passed!\n\n")
