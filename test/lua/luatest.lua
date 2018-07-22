-- See Copyright Notice in the file LICENSE

-- arrays: deep comparison
local function eq (t1, t2, lut)
  if t1 == t2 then return true end
  if type(t1) ~= "table" or type(t2) ~= "table" or #t1 ~= #t2 then
    return false
  end

  lut = lut or {} -- look-up table: are these 2 arrays already compared?
  lut[t1] = lut[t1] or {}
  if lut[t1][t2] then return true end
  lut[t2] = lut[t2] or {}
  lut[t1][t2], lut[t2][t1] = true, true

  for k,v in ipairs (t1) do
    if not eq (t2[k], v, lut) then return false end -- recursion
  end
  return true
end

-- a "nil GUID", to be used instead of nils in datasets
local NT = "b5f74fe5-46f4-483a-8321-e58ba2fa0e17"

-- pack vararg in table, replacing nils with "NT" items
local function packNT (...)
  local t = {}
  for i=1, select ("#", ...) do
    local v = select (i, ...)
    t[i] = (v == nil) and NT or v
  end
  return t
end

-- unpack table into vararg, replacing "NT" items with nils
local function unpackNT (t)
  local len = #t
  local function unpack_from (i)
    local v = t[i]
    if v == NT then v = nil end
    if i == len then return v end
    return v, unpack_from (i+1)
  end
  if len > 0 then return unpack_from (1) end
end

-- print results (deep into arrays)
local function print_results (val, indent, lut)
  indent = indent or ""
  lut = lut or {} -- look-up table
  local str = tostring (val)
  if type (val) == "table" then
    if lut[val] then
      io.write (indent, str, "\n")
    else
      lut[val] = true
      io.write (indent, str, "\n")
      for i,v in ipairs (val) do
        print_results (v, "  " .. indent, lut) -- recursion
      end
    end
  else
    io.write (indent, val == NT and "nil" or str, "\n")
  end
end

-- returns:
--  1) true, if success; false, if failure
--  2) test results table or error_message
local function test_function (test, func)
  local res
  local t = packNT (pcall (func, unpackNT (test[1])))
  if t[1] then
    table.remove (t, 1)
    res = t
    if alien then
      local subject = test[1][1]
      local buf = alien.buffer (#subject)
      if #subject > 0 then
        alien.memmove (buf:topointer (), subject, #subject)
      end
      test[1][1] = buf
      local t = packNT (pcall (func, unpackNT (test[1])))
      if t[1] then
        table.remove (t, 1)
        res = t
      else
        print "alien test failed"
        res = t[2] --> error_message
      end
    end
  else
    res = t[2] --> error_message
  end
  local how = (type (res) == type (test[2])) and
    (type (res) == "string" or eq (res, test[2])) -- allow error messages to differ
  return how, res
end

-- returns:
--  1) true, if success; false, if failure
--  2) test results table or error_message
--  3) test results table or error_message
local function test_method (test, constructor, name)
  local res1, res2
  local subject = test[2][1]
  local ok, r = pcall (constructor, unpackNT (test[1]))
  if ok then
    local t = packNT (pcall (r[name], r, unpackNT (test[2])))
    if t[1] then
      table.remove (t, 1)
      res1, res2 = t
    else
      res1, res2 = 2, t[2] --> 2, error_message
    end
  else
    res1, res2 = 1, r  --> 1, error_message
  end
  return eq (res1, test[3]), res1, res2
end

-- returns: a list of failed tests
local function test_set (set, lib, verbose)
  local list = {}

  if type (set.Func) == "function" then
    local func = set.Func

    for i,test in ipairs (set) do
      if verbose then
        io.write ("    running function test "..i.."...")
        io.flush ()
      end
      local ok, res = test_function (test, func)
      if not ok then
        if verbose then io.stdout:write("failed!\n") end
        table.insert (list, {i=i, test[2], res})
      elseif verbose then
        io.write ("passed\n")
        io.flush ()
      end
    end

  elseif type (set.Method) == "string" then
    for i,test in ipairs (set) do
      if verbose then
        io.write ("    running method test "..i.."...")
        io.flush ()
      end
      local ok, res1, res2 = test_method (test, lib.new, set.Method)
      if not ok then
        if verbose then io.stdout:write("failed!\n") end
        table.insert (list, {i=i, test[3], res1, res2})
      elseif verbose then
        io.write ("passed\n")
        io.flush ()
      end
    end

  else
    error ("neither set.Func nor set.Method is valid")
  end

  return list
end

return {
  eq = eq,
  NT = NT,
  print_results = print_results,
  test_function = test_function,
  test_method = test_method,
  test_set = test_set,
}
