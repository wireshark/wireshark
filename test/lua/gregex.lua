
-- Tests for GLib Regex functions
-- written by Hadriel Kaplan, based on Lrexlib's test suite
-- This is a test script for tshark/wireshark.
-- This script runs inside tshark/wireshark, so to run it do:
-- tshark -r empty.cap -X lua_script:<path_to_testdir>/lua/gregex.lua -X lua_script1:glib
--
-- if you have to give addtional paths to find the dependent lua files,
-- use the '-X lua_script1:' syntax to add more arguments
--
-- available arguments:
--  -d<dir> provides path directory for lua include files
--  -v      verbose mode
--  -V      very verbose mode


-- save args before we do anything else
local args = {...}
for i,v in ipairs(args) do
  print(i.." = "..v)
end

local function testing(...)
	print("---- Testing "..tostring(...).." ----")
end

local count = 0

local function test(name, ...)
  count = count + 1
	io.write("test "..name.."-"..count.."...")
	if (...) == true then
		io.write("passed\n")
    io.flush()
	else
		io.write("failed!\n")
    io.flush()
		error(name.." test failed!")
	end
end

-------------  First test some basic stuff to make sure we're sane -----------

print("Lua version: ".._VERSION)

testing("Lrexlib GLib Regex library")

local lib = GRegex
test("global",_G.GRegex == lib)

for name, val in pairs(lib) do
	print("\t"..name.." = "..type(val))
end

test("class",type(lib) == 'table')
test("class",type(lib._VERSION) == 'string')
test("class",type(lib.find) == 'function')
test("class",type(lib.compile_flags) == 'function')
test("class",type(lib.match_flags) == 'function')
test("class",type(lib.flags) == 'function')
test("class",type(lib.gsub) == 'function')
test("class",type(lib.gmatch) == 'function')
test("class",type(lib.new) == 'function')
test("class",type(lib.match) == 'function')
test("class",type(lib.split) == 'function')
test("class",type(lib.version) == 'function')

testing("info and flags")

test("typeof",typeof(lib) == 'GRegex')

print(lib._VERSION)
print("Glib version = "..lib.version())

local function getTSize(t)
  local c = 0
  for k,v in pairs(t) do
    -- print(k.." = "..v)
    c = c + 1
  end
  return c
end

local flags = lib.flags()

-- print("size = "..c)
-- it's 84 for newer GLib, 61 for older
test("flags", getTSize(flags) > 60)
test("cflags", getTSize(lib.compile_flags()) > 15)
test("eflags", getTSize(lib.match_flags()) > 8)

testing("new")

local results
local function checkFunc(objname,funcname,...)
  results = { pcall(objname[funcname],...) }
  if results[1] then
    return true
  end
  -- print("Got this error: '"..tostring(results[2]).."'")
  return false
end

test("new", checkFunc(lib,"new",".*"))
test("new", checkFunc(lib,"new",""))
test("new", checkFunc(lib,"new","(hello|world)"))

test("new_err", not checkFunc(lib,"new","*"))
test("new_err", not checkFunc(lib,"new"))
test("new_err", not checkFunc(lib,"new","(hello|world"))
test("new_err", not checkFunc(lib,"new","[0-9"))
-- invalid compile flag
test("new_err", not checkFunc(lib,"new","[0-9]",flags.PARTIAL))


local val1 = "hello world foo bar"
local val2 = "hello wORld FOO bar"
local patt = "hello (world) (.*) bar"
local rgx = lib.new(patt)
local rgx2 = lib.new(patt,flags.CASELESS)

testing("typeof")
test("typeof",typeof(rgx) == 'GRegex')
test("typeof",typeof(rgx2) == 'GRegex')

testing("match")
test("match", checkFunc(lib,"match", val1,patt, 1, flags.CASELESS) and results[2] == "world" and results[3] == "foo")
test("match", checkFunc(lib,"match", val2,patt, 1, flags.CASELESS) and results[2] == "wORld" and results[3] == "FOO")
test("match", checkFunc(lib,"match", val1,rgx) and results[2] == "world" and results[3] == "foo")
test("match", checkFunc(rgx,"match", rgx,val1) and results[2] == "world" and results[3] == "foo")
test("match", checkFunc(rgx2,"match", rgx2,val2, 1) and results[2] == "wORld" and results[3] == "FOO")

-- different offset won't match this pattern
test("match_err", checkFunc(rgx2,"match", rgx2,val2, 4) and results[2] == nil)

-- invalid compile flag
test("match_err", not checkFunc(lib,"match", val1,patt, 1, flags.PARTIAL))
-- invalid match flag
test("match_err", not checkFunc(rgx,"match", rgx,val1, 1, flags.CASELESS))

testing("find")

test("find", checkFunc(lib,"find", val1,patt) and results[2] == 1 and results[3] == val1:len()
  and results[4] == "world" and results[5] == "foo")
test("find", checkFunc(lib,"find", val1,rgx) and results[2] == 1 and results[3] == val1:len()
  and results[4] == "world" and results[5] == "foo")
test("find", checkFunc(rgx,"find", rgx,val1) and results[2] == 1 and results[3] == val1:len()
  and results[4] == "world" and results[5] == "foo")

testing("match")

--checkFunc(rgx,"exec", rgx,val1)
--print(results[4][3],results[4][4])
test("exec", checkFunc(rgx,"exec", rgx,val1) and results[2] == 1 and results[3] == val1:len()
  and results[4][1] == 7 and results[4][2] == 11 and results[4][3] == 13 and results[4][4] == 15)

print("\n----------------------------------------------------------\n")

------- OK, we're sane, so run all the library's real tests ---------

testing("Lrexlib-provided tests")

-- we're not using the "real" lib name
local GLIBNAME = "GRegex"
local isglobal = true

do
  local dir
  for i = 1, select ("#", ...)  do
    local arg = select (i, ...)
    --print(arg)
    if arg:sub(1,2) == "-d" then
      dir = arg:sub(3)
    end
  end
  dir = dir:gsub("[/\\]+$", "")
  local path = dir .. "/?.lua;"
  if package.path:sub(1, #path) ~= path then
    package.path = path .. package.path
  end
end

local luatest = require "luatest"

-- returns: number of failures
local function test_library (libname, setfile, verbose, really_verbose)
  if verbose then
    print (("[lib: %s; file: %s]"):format (libname, setfile))
  end
  local lib = isglobal and _G[libname] or require (libname)
  local f = require (setfile)
  local sets = f (libname, isglobal)

  local n = 0 -- number of failures
  for _, set in ipairs (sets) do
    if verbose then
      print (set.Name or "Unnamed set")
    end
    local err = luatest.test_set (set, lib, really_verbose)
    if verbose then
      for _,v in ipairs (err) do
        print ("\nTest " .. v.i)
        print ("  Expected result:\n  "..tostring(v))
        luatest.print_results (v[1], "      ")
        table.remove(v,1)
        print ("\n  Got:")
        luatest.print_results (v, "    ")
      end
    end
    n = n + #err
  end
  if verbose then
    print ""
  end

  return n
end

local avail_tests = {
  posix     = { lib = "rex_posix",   "common_sets", "posix_sets" },
  gnu       = { lib = "rex_gnu",     "common_sets", "emacs_sets", "gnu_sets" },
  oniguruma = { lib = "rex_onig",    "common_sets", "oniguruma_sets", },
  pcre      = { lib = "rex_pcre",    "common_sets", "pcre_sets", "pcre_sets2", },
  glib      = { lib = GLIBNAME,      "common_sets", "pcre_sets", "pcre_sets2", "glib_sets" },
  spencer   = { lib = "rex_spencer", "common_sets", "posix_sets", "spencer_sets" },
  tre       = { lib = "rex_tre",     "common_sets", "posix_sets", "spencer_sets", --[["tre_sets"]] },
}

do
  local verbose, really_verbose, tests, nerr = false, false, {}, 0
  local dir

  -- check arguments
  for i = 1, select ("#", ...)  do
    local arg = select (i, ...)
    --print(arg)
    if arg:sub(1,1) == "-" then
      if arg == "-v" then
        verbose = true
      elseif arg == "-V" then
        verbose = true
        really_verbose = true
      elseif arg:sub(1,2) == "-d" then
        dir = arg:sub(3)
      end
    else
      if avail_tests[arg] then
        tests[#tests+1] = avail_tests[arg]
      else
        error ("invalid argument: [" .. arg .. "]")
      end
    end
  end
  assert (#tests > 0, "no library specified")
  -- give priority to libraries located in the specified directory
  if dir and not isglobal then
    dir = dir:gsub("[/\\]+$", "")
    for _, ext in ipairs {"dll", "so", "dylib"} do
      if package.cpath:match ("%?%." .. ext) then
        local cpath = dir .. "/?." .. ext .. ";"
        if package.cpath:sub(1, #cpath) ~= cpath then
          package.cpath = cpath .. package.cpath
        end
        break
      end
    end
  end
  -- do tests
  for _, test in ipairs (tests) do
    package.loaded[test.lib] = nil -- to force-reload the tested library
    for _, setfile in ipairs (test) do
      nerr = nerr + test_library (test.lib, setfile, verbose, really_verbose)
    end
  end
  print ("Total number of failures: " .. nerr)

  assert(nerr == 0, "Test failed!")
end




print("\n-----------------------------\n")

print("All tests passed!\n\n")
