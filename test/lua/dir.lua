-- test script for wslua Dir functions

------------- helper funcs ------------

local total_tests = 0

local function testing(name)
    print("---- Testing "..name.." ---- ")
end

local function test(name, ...)
    total_tests = total_tests + 1
    io.stdout:write("test "..name.."-"..total_tests.."...")
    if (...) == true then
        io.stdout:write("passed\n")
        return true
    else
        io.stdout:write("failed!\n")
        error(name.." test failed!")
    end
end

-- the following are so we can use pcall (which needs a function to call)
local function callDirFuncBase(name, t)
    t.result = Dir[name]()
    return true
end

local function callDirFunc(name, val, t)
    t.result = Dir[name](val)
    return true
end

local function makeFile(filename)
    local f = io.open(filename, "w")
    if not f then
        error ("failed to make file"..filename.." in directory\n"..
               "make sure to delete 'temp' directory before running again")
    end
    f:write("fooobarrloo")
    f:close()
    return true
end

--------------------------

-- for our called function results
local t = {}

testing("Dir basics")

test("global", _G.Dir               ~= nil)
test("global", type(Dir.make)       == 'function')
test("global", type(Dir.remove)     == 'function')
test("global", type(Dir.remove_all) == 'function')
test("global", type(Dir.open)       == 'function')
test("global", type(Dir.close)      == 'function')
test("global", type(Dir.exists)     == 'function')
test("global", type(Dir.personal_config_path)  == 'function')
test("global", type(Dir.global_config_path)    == 'function')
test("global", type(Dir.personal_plugins_path) == 'function')
test("global", type(Dir.global_plugins_path)   == 'function')

testing("Dir paths/filenames")

test("Dir.__FILE__", __FILE__ ~= nil)
test("Dir.__DIR__", __DIR__ ~= nil)
test("Dir.exists", pcall(callDirFunc, "exists", "temp", t))
test("Dir.personal_config_path",  pcall(callDirFuncBase, "personal_config_path", t))
test("Dir.global_config_path",    pcall(callDirFuncBase, "global_config_path", t))
test("Dir.personal_plugins_path", pcall(callDirFuncBase, "personal_plugins_path", t))
test("Dir.global_plugins_path",   pcall(callDirFuncBase, "global_plugins_path", t))

print("\nFor your information, I got the following info:\n")
print("__FILE__ = '" .. __FILE__ .. "'")
print("__DIR__  = '" .. __DIR__  .. "'")
print("personal_config_path  = '" .. Dir.personal_config_path() .. "'")
print("global_config_path    = '" .. Dir.global_config_path() .. "'")
print("personal_plugins_path = '" .. Dir.personal_plugins_path() .. "'")
print("global_plugins_path   = '" .. Dir.global_plugins_path() .. "'")
print("\n")

testing("Directory manipulation")

test("Dir.exists", pcall(callDirFunc, "exists", "temp", t))

if t.result == true or t.result == false then
    error("this testsuite requires there be no 'temp' directory or file; please remove it")
end

testing("Dir.make")

test("Dir.make", pcall(callDirFunc, "make", "temp", t) and t.result == true)
test("Dir.exists", pcall(callDirFunc, "exists", "temp", t) and t.result == true)
-- make the same dir, should give false
test("Dir.make", pcall(callDirFunc, "make", "temp", t) and t.result == false)

testing("Dir.remove")

test("Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == true)
test("Dir.exists", pcall(callDirFunc, "exists", "temp", t) and t.result == nil)
test("Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == false)

Dir.make("temp")
makeFile("temp/file.txt")

-- will return nil because temp has a file
test("Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == nil)

testing("Dir.remove_all")

test("Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == true)
test("Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == false)

Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")
test("Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == true)
test("Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == false)

testing("Dir.open")

Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")
test("Dir.open", pcall(callDirFunc, "open", "temp", t))
test("Dir.open", type(t.result) == 'userdata')
test("Dir.open", typeof(t.result) == 'Dir')

io.stdout:write("calling Dir object...")
local dir = t.result
local files = {}
files[dir()] = true
io.stdout:write("passed\n")
files[dir()] = true
files[dir()] = true

test("Dir.call", files["file1.txt"])
test("Dir.call", files["file2.txt"])
test("Dir.call", files["file3.txt"])
test("Dir.call", dir() == nil)
test("Dir.call", dir() == nil)

testing("Dir.close")

test("Dir.close", pcall(callDirFunc, "close", dir, t))
test("Dir.close", pcall(callDirFunc, "close", dir, t))

testing("Negative testing 1")
-- now try breaking it
test("Dir.open", pcall(callDirFunc, "open", "temp", t))
dir = t.result
-- call dir() now
files = {}
files[dir()] = true

Dir.remove_all("temp")

-- call it again
files[dir()] = true
files[dir()] = true
test("Dir.call", files["file1.txt"])
test("Dir.call", files["file2.txt"])
test("Dir.call", files["file3.txt"])
test("Dir.close", pcall(callDirFunc, "close", dir, t))

testing("Negative testing 2")
-- do it again, but this time don't do dir() until after removing the files
Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")

test("Dir.open", pcall(callDirFunc, "open", "temp", t))
dir = t.result

Dir.remove_all("temp")
-- now do it
file = dir()
test("Dir.call", file == nil)
test("Dir.close", pcall(callDirFunc, "close", dir, t))


-- negative tests
testing("Negative testing 3")

-- invalid args
test("Dir.make", not pcall(callDirFunc, "make", {}, t))
test("Dir.make", not pcall(callDirFunc, "make", nil, t))
test("Dir.remove", not pcall(callDirFunc, "remove", {}, t))
test("Dir.remove", not pcall(callDirFunc, "remove", nil, t))
test("Dir.remove_all", not pcall(callDirFunc, "remove_all", {}, t))
test("Dir.remove_all", not pcall(callDirFunc, "remove_all", nil, t))
test("Dir.open", not pcall(callDirFunc, "open", {}, t))
test("Dir.open", not pcall(callDirFunc, "open", nil, t))
test("Dir.close", not pcall(callDirFunc, "close", "dir", t))
test("Dir.close", not pcall(callDirFunc, "close", nil, t))


print("\n-----------------------------\n")

print("All tests passed!\n\n")
