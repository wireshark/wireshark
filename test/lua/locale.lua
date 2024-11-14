-- Test script to set the locale before running other Lua scripts

local arg={...}

if #arg >= 2 then
    os.setlocale(arg[1], arg[2])
else
    os.setlocale(arg[1])
end
