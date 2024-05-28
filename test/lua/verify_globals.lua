-- verify_globals.lua

-- ignore things that change on different machines or every release
-- the following items still have to exist, but their values don't have to match
local filter = {
    -- differences by machine
    "DATA_DIR",
    "USER_DIR",
    "package.cpath",
    "package.path",
    "package.loaded",
    "run_user_scripts_when_superuser",
    "running_superuser",

    -- differences in Lua versions
    "_VERSION",
    "package.config",
    "utf8.charpattern" -- some versions allow overlong encodings
 }

-- the following items don't have to exist
local ignore = {
    -- deprecated in Lua 5.3, removed in Lua 5.4
    -- but might appear in 5.4 with 5.3 backwards compatibility mode
    "bit32", -- 5.3+ has bitwise operators, we include BitOp
    "math.atan2", -- use math.atan with two arguments
    "math.cosh",
    "math.log10", -- call math.log with second argument
    "math.sinh",
    "math.tanh",
    "math.pow", -- use x^y
    "math.frexp",
    "math.ldexp", -- use x * 2.0^exp

    -- new in Lua 5.4
    "coroutine.close",
    "debug.setcstacklimit", -- function that existed in 5.4.1, stub-only in 5.4.2+
    "warn"
}


local arg={...} -- get passed-in args

-- arg1 = path to find inspect
-- arg2 = filename to read in (optional, unless 'verify' is set)
-- arg3 = 'verify' to verify all of read-in file is in _G (default); 'new' to output all items in _G that are not in read-in file
-- arg4 = 'nometa' to ignore metatables; 'meta' otherwise (default)

local add_path = "lua/?.lua;"
if #arg > 0 then
    add_path = arg[1].."?.lua;"
end

print("package.path = " .. package.path)

-- need the path to find inspect.lua
local old_path = package.path
package.path = add_path .. package.path

local inspect = require("inspect")

package.path = old_path -- return path to original

print("-- Wireshark version: " .. get_version())

if #arg == 1 then
    -- no more args, so just output globals
    print(inspect(_G, { serialize = true, filter = inspect.makeFilter(filter) }))
    return
end

local file = assert(io.open(arg[2], "r"))
local input = file:read("*all")
input = inspect.marshal(input)

local nometa = false
if #arg > 3 and arg[4] == "nometa" then
    nometa = true
end

if #arg == 2 or arg[3] == "verify" then
    print(string.rep("\n", 2))
    print("Verifying input file '"..arg[2].."' is contained within the global table")
    local ret, diff = inspect.compare(input, _G, {
        ['filter'] = inspect.makeFilter(filter),
        ['ignore'] = inspect.makeFilter(ignore),
        ['nonumber'] = true,
        ['nometa'] = nometa
        })
    if not ret then
        print("Comparison failed - global table does not have all the items in the input file!")
        print(string.rep("\n", 2))
        print(string.rep("-", 80))
        print("Differences are:")
        print(inspect(diff))
    else
        print("\n-----------------------------\n")
        print("All tests passed!\n\n")
    end
    return
elseif #arg > 2 and arg[3] == "new" then
    local ret, diff = inspect.compare(_G, input, {
        ['filter'] = inspect.makeFilter(filter),
        ['ignore'] = inspect.makeFilter(ignore),
        ['nonumber'] = true,
        ['keep'] = true,
        ['nometa'] = nometa
        })
    if not ret then
        print(inspect(diff))
    else
        print("\n-----------------------------\n")
        print("No new items!\n\n")
    end
end

