-- test script for wslua utility functions

local testlib = require("testlib")

local GET_PREF = "get"
local SET_PREF = "set"
local RESET_PREF = "reset"
local OTHER = "other"
testlib.init( {
    [GET_PREF] = 14,
    [SET_PREF] = 37,
    [RESET_PREF] = 11,
    [OTHER] = 0
} )

local console_open

--------------------------

-- Note: This tests expects some specific default values
testlib.testing("get_preference")

success = pcall(get_preference)
testlib.test(GET_PREF,"get_preference-empty-0", not success)
testlib.test(GET_PREF,"get_preference-empty-1",get_preference("") == nil)
testlib.test(GET_PREF,"get_preference-unknown-0",get_preference("g") == nil)
testlib.test(GET_PREF,"get_preference-unknown-1",get_preference("gui") == nil)
testlib.test(GET_PREF,"get_preference-unknown-2",get_preference("gui.") == nil)
testlib.test(GET_PREF,"get_preference-unknown-3",get_preference("gui.ask") == nil)
testlib.test(GET_PREF,"get_preference-unknown-4",get_preference("ugi.ask_unsaved") == nil)
testlib.test(GET_PREF,"get_preference-uint-0",get_preference("gui.fileopen.preview") == 3)
testlib.test(GET_PREF,"get_preference-bool-0",get_preference("gui.ask_unsaved") == true)
testlib.test(GET_PREF,"get_preference-bool-1",get_preference("gui.interfaces_show_hidden") == false)
-- gui.console_open is persistent (in the Windows registry) and for that
-- reason does not have a default value.
console_open = get_preference("gui.console_open")
testlib.test(GET_PREF,"get_preference-enum-0",console_open == "NEVER" or console_open == "AUTOMATIC" or console_open == "ALWAYS")
testlib.test(GET_PREF,"get_preference-string-0",get_preference("gui.window_title") == "")
testlib.test(GET_PREF,"get_preference-range-0",get_preference("http.tls.port") == "443")
success = pcall(get_preference, "user_dlt.encaps_table")
testlib.test(GET_PREF,"get_preference-uat-0", not success)

--------------------------

testlib.testing("set_preference")

success = pcall(set_preference)
testlib.test(SET_PREF,"set_preference-empty-0", not success)
testlib.test(SET_PREF,"set_preference-empty-1",set_preference("") == nil)
testlib.test(SET_PREF,"set_preference-unknown-0",set_preference("g") == nil)
testlib.test(SET_PREF,"set_preference-unknown-1",set_preference("gui") == nil)
testlib.test(SET_PREF,"set_preference-unknown-2",set_preference("gui.") == nil)
testlib.test(SET_PREF,"set_preference-unknown-3",set_preference("gui.ask") == nil)
testlib.test(SET_PREF,"set_preference-unknown-4",set_preference("ugi.ask_unsaved") == nil)
success = pcall(set_preference,"gui.fileopen.preview")
testlib.test(SET_PREF,"set_preference-uint-0", not success)
success = pcall(set_preference,"gui.fileopen.preview",true)
testlib.test(SET_PREF,"set_preference-uint-1", not success)
success = pcall(set_preference,"gui.fileopen.preview","string")
testlib.test(SET_PREF,"set_preference-uint-2", not success)
testlib.test(SET_PREF,"set_preference-uint-3",set_preference("gui.fileopen.preview",3) == false)
testlib.test(SET_PREF,"set_preference-uint-4",set_preference("gui.fileopen.preview",42) == true)
testlib.test(SET_PREF,"set_preference-uint-4-get",get_preference("gui.fileopen.preview") == 42)
success = pcall(set_preference,"gui.ask_unsaved")
testlib.test(SET_PREF,"set_preference-bool-0", not success)
success = pcall(set_preference,"gui.ask_unsaved",42)
testlib.test(SET_PREF,"set_preference-bool-1", not success)
success = pcall(set_preference,"gui.ask_unsaved","string")
testlib.test(SET_PREF,"set_preference-bool-2", not success)
testlib.test(SET_PREF,"set_preference-bool-3",set_preference("gui.ask_unsaved", true) == false)
testlib.test(SET_PREF,"set_preference-bool-4",set_preference("gui.ask_unsaved", false) == true)
success = pcall(set_preference,"gui.console_open")
testlib.test(SET_PREF,"set_preference-enum-0", not success)
success = pcall(set_preference,"gui.console_open",true)
testlib.test(SET_PREF,"set_preference-enum-1", not success)
-- false means unchanged
testlib.test(SET_PREF,"set_preference-enum-2",set_preference("gui.console_open",console_open) == false)
success = pcall(set_preference,"gui.window_title")
testlib.test(SET_PREF,"set_preference-string-0", not success)
success = pcall(set_preference,"gui.window_title",true)
testlib.test(SET_PREF,"set_preference-string-1", not success)
testlib.test(SET_PREF,"set_preference-string-2",set_preference("gui.window_title","Title") == true)
testlib.test(SET_PREF,"set_preference-string-2-get",get_preference("gui.window_title") == "Title")
testlib.test(SET_PREF,"set_preference-string-3",set_preference("gui.window_title","Title") == false)
testlib.test(SET_PREF,"set_preference-string-4",set_preference("gui.window_title","") == true)
testlib.test(SET_PREF,"set_preference-string-4-get",get_preference("gui.window_title") == "")
testlib.test(SET_PREF,"set_preference-string-5",set_preference("gui.window_title","") == false)
success = pcall(set_preference,"http.tls.port")
testlib.test(SET_PREF,"set_preference-range-0", not success)
success = pcall(set_preference,"http.tls.port","65536") -- Number too big
testlib.test(SET_PREF,"set_preference-range-1", not success)
success = pcall(set_preference,"http.tls.port","http") -- Syntax error
testlib.test(SET_PREF,"set_preference-range-2", not success)
testlib.test(SET_PREF,"set_preference-range-3",set_preference("http.tls.port","443") == false)
testlib.test(SET_PREF,"set_preference-range-4",set_preference("http.tls.port","443-444") == true)
testlib.test(SET_PREF,"set_preference-range-4-get",get_preference("http.tls.port") == "443-444")
testlib.test(SET_PREF,"set_preference-range-5",set_preference("http.tls.port","443-444") == false)
success = pcall(set_preference, "user_dlt.encaps_table")
testlib.test(SET_PREF,"set_preference-uat-0", not success)

--------------------------

testlib.testing("reset_preference")

success = pcall(set_preference)
testlib.test(RESET_PREF,"reset_preference-empty-0", not success)
testlib.test(RESET_PREF,"reset_preference-empty-1",reset_preference("") == nil)
testlib.test(RESET_PREF,"reset_preference-unknown-0",reset_preference("unknown") == nil)
testlib.test(RESET_PREF,"reset_preference-uint-0",reset_preference("gui.fileopen.preview") == true)
testlib.test(RESET_PREF,"reset_preference-uint-0-get",get_preference("gui.fileopen.preview") == 3)
testlib.test(RESET_PREF,"reset_preference-bool-0",reset_preference("gui.ask_unsaved") == true)
testlib.test(RESET_PREF,"reset_preference-bool-0-get",get_preference("gui.ask_unsaved") == true)
testlib.test(RESET_PREF,"reset_preference-string-0",reset_preference("gui.window_title") == true)
testlib.test(RESET_PREF,"reset_preference-string-0-get",get_preference("gui.window_title") == "")
testlib.test(RESET_PREF,"reset_preference-range-0",reset_preference("http.tls.port") == true)
testlib.test(RESET_PREF,"reset_preference-range-0-get",get_preference("http.tls.port") == "443")

testlib.getResults()
