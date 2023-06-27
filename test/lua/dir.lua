-- test script for wslua Dir functions

local testlib = require("testlib")
local OTHER = "other"
testlib.init( { [OTHER] = 0 } )

------------- helper funcs ------------

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

testlib.testing("Dir basics")

testlib.test(OTHER,"global", _G.Dir               ~= nil)
testlib.test(OTHER,"global", type(Dir.make)       == 'function')
testlib.test(OTHER,"global", type(Dir.remove)     == 'function')
testlib.test(OTHER,"global", type(Dir.remove_all) == 'function')
testlib.test(OTHER,"global", type(Dir.open)       == 'function')
testlib.test(OTHER,"global", type(Dir.close)      == 'function')
testlib.test(OTHER,"global", type(Dir.exists)     == 'function')
testlib.test(OTHER,"global", type(Dir.personal_config_path)  == 'function')
testlib.test(OTHER,"global", type(Dir.global_config_path)    == 'function')
testlib.test(OTHER,"global", type(Dir.personal_plugins_path) == 'function')
testlib.test(OTHER,"global", type(Dir.global_plugins_path)   == 'function')

testlib.testing("Dir paths/filenames")

testlib.test(OTHER,"Dir.__FILE__", __FILE__ ~= nil)
testlib.test(OTHER,"Dir.__DIR__", __DIR__ ~= nil)
testlib.test(OTHER,"Dir.exists", pcall(callDirFunc, "exists", "temp", t))
testlib.test(OTHER,"Dir.personal_config_path",  pcall(callDirFuncBase, "personal_config_path", t))
testlib.test(OTHER,"Dir.global_config_path",    pcall(callDirFuncBase, "global_config_path", t))
testlib.test(OTHER,"Dir.personal_plugins_path", pcall(callDirFuncBase, "personal_plugins_path", t))
testlib.test(OTHER,"Dir.global_plugins_path",   pcall(callDirFuncBase, "global_plugins_path", t))

-- Users expect trailing slashes for DATA_DIR and USER_DIR (bug 14619).
local dirsep = package.config:sub(1,1)
testlib.test(OTHER,"DATA_DIR", string.sub(DATA_DIR, -1) == dirsep)
testlib.test(OTHER,"USER_DIR", string.sub(USER_DIR, -1) == dirsep)

print("\nFor your information, I got the following info:\n")
print("__FILE__ = '" .. __FILE__ .. "'")
print("__DIR__  = '" .. __DIR__  .. "'")
print("personal_config_path  = '" .. Dir.personal_config_path() .. "'")
print("global_config_path    = '" .. Dir.global_config_path() .. "'")
print("personal_plugins_path = '" .. Dir.personal_plugins_path() .. "'")
print("global_plugins_path   = '" .. Dir.global_plugins_path() .. "'")
print("\n")

testlib.testing("Directory manipulation")

testlib.test(OTHER,"Dir.exists", pcall(callDirFunc, "exists", "temp", t))

if t.result == true or t.result == false then
    error("this testsuite requires there be no 'temp' directory or file; please remove it")
end

testlib.testing("Dir.make")

testlib.test(OTHER,"Dir.make", pcall(callDirFunc, "make", "temp", t) and t.result == true)
testlib.test(OTHER,"Dir.exists", pcall(callDirFunc, "exists", "temp", t) and t.result == true)
-- make the same dir, should give false
testlib.test(OTHER,"Dir.make", pcall(callDirFunc, "make", "temp", t) and t.result == false)

testlib.testing("Dir.remove")

testlib.test(OTHER,"Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == true)
testlib.test(OTHER,"Dir.exists", pcall(callDirFunc, "exists", "temp", t) and t.result == nil)
testlib.test(OTHER,"Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == false)

Dir.make("temp")
makeFile("temp/file.txt")

-- will return nil because temp has a file
testlib.test(OTHER,"Dir.remove", pcall(callDirFunc, "remove", "temp", t) and t.result == nil)

testlib.testing("Dir.remove_all")

testlib.test(OTHER,"Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == true)
testlib.test(OTHER,"Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == false)

Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")
testlib.test(OTHER,"Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == true)
testlib.test(OTHER,"Dir.remove_all", pcall(callDirFunc, "remove_all", "temp", t) and t.result == false)

testlib.testing("Dir.open")

Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")
testlib.test(OTHER,"Dir.open", pcall(callDirFunc, "open", "temp", t))
testlib.test(OTHER,"Dir.open", type(t.result) == 'userdata')
testlib.test(OTHER,"Dir.open", typeof(t.result) == 'Dir')

io.stdout:write("calling Dir object...")
local dir = t.result
local files = {}
files[dir()] = true
io.stdout:write("passed\n")
files[dir()] = true
files[dir()] = true

testlib.test(OTHER,"Dir.call", files["file1.txt"])
testlib.test(OTHER,"Dir.call", files["file2.txt"])
testlib.test(OTHER,"Dir.call", files["file3.txt"])
testlib.test(OTHER,"Dir.call", dir() == nil)
testlib.test(OTHER,"Dir.call", dir() == nil)

testlib.testing("Dir.close")

testlib.test(OTHER,"Dir.close", pcall(callDirFunc, "close", dir, t))
testlib.test(OTHER,"Dir.close", pcall(callDirFunc, "close", dir, t))

testlib.testing("Negative testing 1")
-- now try breaking it
testlib.test(OTHER,"Dir.open", pcall(callDirFunc, "open", "temp", t))
dir = t.result
-- call dir() now
files = {}
files[dir()] = true

Dir.remove_all("temp")

-- call it again
files[dir()] = true
files[dir()] = true
testlib.test(OTHER,"Dir.call", files["file1.txt"])
testlib.test(OTHER,"Dir.call", files["file2.txt"])
testlib.test(OTHER,"Dir.call", files["file3.txt"])
testlib.test(OTHER,"Dir.close", pcall(callDirFunc, "close", dir, t))

testlib.testing("Negative testing 2")
-- do it again, but this time don't do dir() until after removing the files
Dir.make("temp")
makeFile("temp/file1.txt")
makeFile("temp/file2.txt")
makeFile("temp/file3.txt")

testlib.test(OTHER,"Dir.open", pcall(callDirFunc, "open", "temp", t))
dir = t.result

Dir.remove_all("temp")
-- now do it
file = dir()
testlib.test(OTHER,"Dir.call", file == nil)
testlib.test(OTHER,"Dir.close", pcall(callDirFunc, "close", dir, t))


-- negative tests
testlib.testing("Negative testing 3")

-- invalid args
testlib.test(OTHER,"Dir.make", not pcall(callDirFunc, "make", {}, t))
testlib.test(OTHER,"Dir.make", not pcall(callDirFunc, "make", nil, t))
testlib.test(OTHER,"Dir.remove", not pcall(callDirFunc, "remove", {}, t))
testlib.test(OTHER,"Dir.remove", not pcall(callDirFunc, "remove", nil, t))
testlib.test(OTHER,"Dir.remove_all", not pcall(callDirFunc, "remove_all", {}, t))
testlib.test(OTHER,"Dir.remove_all", not pcall(callDirFunc, "remove_all", nil, t))
testlib.test(OTHER,"Dir.open", not pcall(callDirFunc, "open", {}, t))
testlib.test(OTHER,"Dir.open", not pcall(callDirFunc, "open", nil, t))
testlib.test(OTHER,"Dir.close", not pcall(callDirFunc, "close", "dir", t))
testlib.test(OTHER,"Dir.close", not pcall(callDirFunc, "close", nil, t))


print("\n-----------------------------\n")

testlib.getResults()
