-------------------------------------------------------------------
-- This was changed for Wireshark's use by Hadriel Kaplan.
--
-- Changes made:
-- * provided 'serialize' option to output serialized info (ie, can be marshaled),
--   though note that serializing functions/metatables/userdata/threads will not
--   magically make them be their original type when marshaled.
-- * provided 'notostring' option, which if true will disabled calling __tostring
--   metamethod of tables.
-- * made it always print the index number of numbered-array entries, and on separate
--   lines like the normal key'd entries (much easier to read this way I think)
-- New public functions:
-- inspect.compare(first,second[,options])
-- inspect.marshal(inString[,options])
-- inspect.makeFilter(arrayTable)
--
-- For the *changes*:
-- Copyright (c) 2014, Hadriel Kaplan
-- My change to the code is in the Public Domain, or the BSD (3 clause) license if
-- Public Domain does not apply in your country, or you would prefer a BSD license.
-- But the original code is still under Enrique García Cota's MIT license (below).
-------------------------------------------------------------------

local inspect ={
  _VERSION = 'inspect.lua 2.0.0 - with changes',
  _URL     = 'http://github.com/kikito/inspect.lua',
  _DESCRIPTION = 'human-readable representations of tables',
  _LICENSE = [[
    MIT LICENSE

    Copyright (c) 2013 Enrique García Cota

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  ]],
  _TINDEX_KEY    = '<index>', -- the key name to use for index number entries for tables
  _DEPTH_MARKER  = " ['<depth>'] = true " -- instead of printing '...' we print this
}

-- Apostrophizes the string if it has quotes, but not apostrophes
-- Otherwise, it returns a regular quoted string
local function smartQuote(str)
  if str:match('"') and not str:match("'") then
    return "'" .. str .. "'"
  end
  return '"' .. str:gsub('"', '\\"') .. '"'
end

local controlCharsTranslation = {
  ["\a"] = "\\a",  ["\b"] = "\\b", ["\f"] = "\\f",  ["\n"] = "\\n",
  ["\r"] = "\\r",  ["\t"] = "\\t", ["\v"] = "\\v"
}

local function escapeChar(c) return controlCharsTranslation[c] end

local function escape(str)
  local result = str:gsub("\\", "\\\\"):gsub("(%c)", escapeChar)
  return result
end

local function isIdentifier(str)
  return type(str) == 'string' and str:match( "^[_%a][_%a%d]*$" )
end

local function isArrayKey(k, length)
  return type(k) == 'number' and 1 <= k and k <= length
end

local function isDictionaryKey(k, length)
  return not isArrayKey(k, length)
end

local defaultTypeOrders = {
  ['number']   = 1, ['boolean']  = 2, ['string'] = 3, ['table'] = 4,
  ['function'] = 5, ['userdata'] = 6, ['thread'] = 7
}

local function sortKeys(a, b)
  local ta, tb = type(a), type(b)

  -- strings and numbers are sorted numerically/alphabetically
  if ta == tb and (ta == 'string' or ta == 'number') then return a < b end

  local dta, dtb = defaultTypeOrders[ta], defaultTypeOrders[tb]
  -- Two default types are compared according to the defaultTypeOrders table
  if dta and dtb then return defaultTypeOrders[ta] < defaultTypeOrders[tb]
  elseif dta     then return true  -- default types before custom ones
  elseif dtb     then return false -- custom types after default ones
  end

  -- custom types are sorted out alphabetically
  return ta < tb
end

local function getDictionaryKeys(t)
  local keys, length = {}, #t
  for k,_ in pairs(t) do
    if isDictionaryKey(k, length) then table.insert(keys, k) end
  end
  table.sort(keys, sortKeys)
  return keys
end

local function getToStringResultSafely(t, mt)
  local __tostring = type(mt) == 'table' and rawget(mt, '__tostring')
  local str, ok
  if type(__tostring) == 'function' then
    ok, str = pcall(__tostring, t)
    str = ok and str or 'error: ' .. tostring(str)
  end
  if type(str) == 'string' and #str > 0 then return str end
end

local maxIdsMetaTable = {
  __index = function(self, typeName)
    rawset(self, typeName, 0)
    return 0
  end
}

local idsMetaTable = {
  __index = function (self, typeName)
    local col = setmetatable({}, {__mode = "kv"})
    rawset(self, typeName, col)
    return col
  end
}

local function countTableAppearances(t, tableAppearances)
  tableAppearances = tableAppearances or setmetatable({}, {__mode = "k"})

  if type(t) == 'table' then
    if not tableAppearances[t] then
      tableAppearances[t] = 1
      for k,v in pairs(t) do
        countTableAppearances(k, tableAppearances)
        countTableAppearances(v, tableAppearances)
      end
      countTableAppearances(getmetatable(t), tableAppearances)
    else
      tableAppearances[t] = tableAppearances[t] + 1
    end
  end

  return tableAppearances
end

local function parse_filter(filter)
  if type(filter) == 'function' then return filter end
  -- not a function, so it must be a table or table-like
  filter = type(filter) == 'table' and filter or {filter}
  local dictionary = {}
  for _,v in pairs(filter) do dictionary[v] = true end
  return function(x) return dictionary[x] end
end

local function makePath(path, key)
  local newPath, len = {}, #path
  for i=1, len do newPath[i] = path[i] end
  newPath[len+1] = key
  return newPath
end

-------------------------------------------------------------------
function inspect.inspect(rootObject, options)
  options       = options or {}
  local depth   = options.depth or math.huge
  local filter  = parse_filter(options.filter or {})
  local serialize  = options.serialize

  local depth_marker = inspect._DEPTH_MARKER

  local tableAppearances = countTableAppearances(rootObject)

  local buffer = {}
  local maxIds = setmetatable({}, maxIdsMetaTable)
  local ids    = setmetatable({}, idsMetaTable)
  local level  = 0
  local blen   = 0 -- buffer length

  local function puts(...)
    local args = {...}
    for i=1, #args do
      blen = blen + 1
      buffer[blen] = tostring(args[i])
    end
  end

  -- like puts above, but for things we want as quoted strings
  -- so they become values, as we do if serializing
  local function putv(...)
    blen = blen + 1
    buffer[blen] = "'"
    puts(...)
    blen = blen + 1
    buffer[blen] = "'"
  end

  -- if serializing, using raw strings is unsafe, so we use the full "['key']" style
  local function putk(...)
    blen = blen + 1
    buffer[blen] = "['"
    puts(...)
    blen = blen + 1
    buffer[blen] = "']"
  end

  -- if not serializing, it's all puts
  if not serialize then
    putv = puts
    putk = puts
    depth_marker = '...'
  end

  -- disable using __tostring metamethod
  local getToStringResultSafely = getToStringResultSafely
  if options.notostring or serialize then
    getToStringResultSafely = function() return end
  end

  local function down(f)
    level = level + 1
    f()
    level = level - 1
  end

  local function tabify()
    puts("\n", string.rep("    ", level))
  end

  local function commaControl(needsComma)
    if needsComma then puts(',') end
    return true
  end

  local function alreadyVisited(v)
    return ids[type(v)][v] ~= nil
  end

  local function getId(v)
    local tv = type(v)
    local id = ids[tv][v]
    if not id then
      id         = maxIds[tv] + 1
      maxIds[tv] = id
      ids[tv][v] = id
    end
    return id
  end

  local putValue -- forward declaration that needs to go before putTable & putKey

  local function putKey(k)
    if not serialize and isIdentifier(k) then return puts(k) end
    puts("[")
    putValue(k, {})
    puts("]")
  end

  local function putTable(t, path)
    if alreadyVisited(t) then
      putv('<table ', getId(t), '>')
    elseif level >= depth then
      puts('{', depth_marker, '}')
    else
      if not serialize and tableAppearances[t] > 1 then puts('<', getId(t), '>') end

      local dictKeys          = getDictionaryKeys(t)
      local length            = #t
      local mt                = getmetatable(t)
      local to_string_result  = getToStringResultSafely(t, mt)

      puts('{')
      down(function()
        if to_string_result then
          puts(' -- ', escape(to_string_result))
          if length >= 1 then tabify() end -- tabify the array values
        end

        local needsComma = false

        if serialize and tableAppearances[t] > 1 then
          getId(t)
        end

        for i=1, length do
          needsComma = commaControl(needsComma)
          -- just doing puts(' ') made for ugly arrays
          tabify()
          putKey(i)
          puts(' = ')
          putValue(t[i], makePath(path, i))
        end

        for _,k in ipairs(dictKeys) do
          needsComma = commaControl(needsComma)
          tabify()
          putKey(k)
          puts(' = ')
          putValue(t[k], makePath(path, k))
        end

        if mt then
          needsComma = commaControl(needsComma)
          tabify()
          putk('<metatable>')
          puts(' = ')
          putValue(mt, makePath(path, '<metatable>'))
        end
      end)

      if #dictKeys > 0 or mt then -- dictionary table. Justify closing }
        tabify()
      elseif length > 0 then -- array tables have one extra space before closing }
        puts(' ')
      end

      puts('}')
    end

  end

  -- putvalue is forward-declared before putTable & putKey
  putValue = function(v, path)
    if filter(v, path) then
      putv('<filtered>')
    else
      local tv = type(v)

      if tv == 'string' then
        puts(smartQuote(escape(v)))
      elseif tv == 'number' and v == math.huge then
        putv('<number inf>')
      elseif tv == 'number' or tv == 'boolean' or tv == 'nil' then
        puts(tostring(v))
      elseif tv == 'table' then
        putTable(v, path)
      else
        putv('<',tv,' ',getId(v),'>')
      end
    end
  end

  putValue(rootObject, {})

  return table.concat(buffer)
end

setmetatable(inspect, { __call = function(_, ...) return inspect.inspect(...) end })

-------------------------------------------------------------------

-- The above is very close to Enrique's original inspect library.
-- Below are my main changes.

-------------------------------------------------------------------
-- Given a string generated by inspect() with the serialize option,
-- this function marshals it back into a Lua table/whatever.
-- If the string's table(s) had metatable(s), i.e. "<metatable>" tables,
-- then this keeps them as "<metatable>" subtables unless the option
-- 'nometa' is set to true.
--
-- This function also removes all "<index>" entries.
--
function inspect.marshal(inString, options)
  options     = options or {}
  local index = inspect._TINDEX_KEY

  local function removeIndex(t)
    if type(t) == 'table' then
      t[index] = nil
      for _, v in pairs(t) do
        removeIndex(v)
      end
    end
  end

  local function removeMeta(t)
    if type(t) == 'table' then
      t['<metatable>'] = nil
      for _, v in pairs(t) do
        removeMeta(v)
      end
    end
  end

  -- first skip past comments/empty-lines
  -- warning: super-hack-ish weak
  local pos, ok, dk = 1, true, true
  local fin
  local stop = string.len(inString)
  while ok or dk do
    ok, fin = inString:find("^[%s\r\n]+",pos)
    if ok then pos = fin + 1 end
    dk, fin = inString:find("^%-%-.-\n",pos)
    if dk then pos = fin + 1 end
  end

  if not inString:find("^%s*return[%s%{]",pos) then
    inString = "return " .. inString
  end

  local t = assert(loadstring(inString))()

  removeIndex(t)

  if options.nometa then removeMeta(t) end

  return t
end

-------------------------------------------------------------------

-------------------------------------------------------------------
-- more private functions

-- things like '<function>' are equal to '<function 32>'
local mungetypes = {
  {"^<function ?%d*>",  '<function>'},
  {"^<table ?%d*>",     '<table>'},
  {"^<userdata ?%d*>",  '<userdata>'},
  {"^<thread ?%d*>",    '<thread>'}
}
local function normalizeString(s)
  for _,t in ipairs(mungetypes) do
    if s:find(t[1]) then
      return t[2]
    end
  end
  return s
end

local typetable = {
  ['<function>']  = 'function',
  ['<table>']     = 'table',
  ['<userdata>']  = 'userdata',
  ['<thread>']    = 'thread'
}
local function getType(v)
  local tv = type(v)
  if tv == 'string' then
    tv = typetable[normalizeString(v)] or 'string'
  end
  return tv
end

local function tablelength(t)
  local count = 0
  for _ in pairs(t) do count = count + 1 end
  return count
end

-- for pretty-printing paths, for debug output
-- this is non-optimal, but only gets used in verbose mode anyway
local function serializePath(path)
  local t = {}
  for i,k in ipairs(path) do
    local tk = type(k)
    if isIdentifier(k) then
      t[i] = ((i == 1) and k) or ('.'..k)
    elseif tk == 'string' then
      t[i] = '[' .. smartQuote(escape(k)) .. ']'
    elseif tk == 'number' or tk == 'boolean' then
      t[i] = '[' .. tostring(k) .. ']'
    else
      t[i] = "['<" .. tk .. ">']"
    end
  end
  if #t == 0 then t[1] = '{}' end
  return table.concat(t)
end

-------------------------------------------------------------------

-------------------------------------------------------------------
-- Given one table and another, this function detects if the first is
-- completely contained in the second object. The second can have more
-- entries, but cannot be missing an entry in the first one. Entry values
-- must match as well - i.e., string values are the same, numbers the
-- same, booleans the same.
--
-- The function returns true if the first is in the second, false otherwise.
-- It also returns a table of the diff, which will be empty if they matched.
-- This returned table is structured like the first one passed in,
-- so calling print(inspect(returnedTabled)) will make it pretty print.
--
-- The returned table's members have their values replaced with mismatch
-- information, explaining what the mismatch was. Setting the option "keep"
-- makes it not replace the values, but keep them as they were in the first
-- table.
--
-- By default, the key's values must match in both tables.  If the option
-- 'nonumber' is set, then number values are not compared.  This is useful
-- if they're things that can change (like exported C-code numbers).
--
-- By default, the metatables/"<metatables>" are also compared.  If the option
-- 'nometa' is set, then metatables are not compared, nor does it matter if
-- they exist in either table.
--
-- Like inspect(), there's a 'filter' option, which works the same way:
-- it ignores its value completely in terms of matching, so their string values
-- can be different, but the keys still have to exist.  Sub-tables of
-- such keys (i.e., if the key's value is a table) are not checked/compared.
-- In other words, it's identical to the filter option for inspect().
--
-- The option 'ignore' is similar to 'filter', except matching ones
-- are not checked for existence in the tables at all.
--
-- Setting the 'depth' option applies as in inspect(), to both tables.
--
-- Setting the option 'verbose' makes it print out as it compares, for
-- debugging or test purposes.
--
function inspect.compare(firstTable, secondTable, options)
  options       = options or {}
  local depth   = options.depth or math.huge
  local filter  = parse_filter(options.filter or {})
  local ignore  = parse_filter(options.ignore or {})

  local function puts(...)
    local args = {...}
    for i=1, #args do
      blen = blen + 1
      buffer[blen] = tostring(args[i])
    end
  end

  -- for debug printing
  local function dprint(...)
    local args = {...}
    print(table.concat(args))
  end

  local serializePath = serializePath

  if not options.verbose then
    dprint = function() return end
    serializePath = function() return end
  end

  -- for error message replacing key value
  local function emsg(...)
    local args = {...}
    return(table.concat(args))
  end

  if options.keep then
    emsg = function() return end
  end

  -- declare checkValue here
  local checkValue

  local function checkTable(f, s, path)
    dprint("checking ",serializePath(path)," table contents")

    for k, v in pairs(f) do
      local child = makePath(path, k)

      if not ignore(v,child) then
        local ret, msg = checkValue(v, s[k], child)
        if ret then
          f[k] = nil
        elseif msg then
          f[k] = msg
          dprint(serializePath(child)," ",msg)
        end
      else
        dprint("ignoring ",serializePath(child))
        f[k] = nil
      end
    end
    return tablelength(f) == 0
  end

  -- a wrapper for failure cases in checkValue() that can be handled the same way
  local function compCheck(f,s,func)
    if not func() then
      return false, emsg("mismatched ",getType(f)," values: ",tostring(f)," --> ",tostring(s))
    end
    return true
  end

  -- kinda ugly, but I wanted pretty information output
  checkValue = function(f, s, path)
    local tf = getType(f)

    dprint("checking ",serializePath(path)," (",tf,")")

    if s == nil then
      return false, emsg("missing ",tf,"!")
    elseif tf ~= getType(s) then
      return false, emsg("type mismatch (",tf,") --> (",getType(s),")")
    elseif type(f) == 'table' then
      return checkTable(f, s, path)
    end

    return compCheck(f,s,function()
      if tf == 'string' or tf == 'boolean' then
        return f == s
      elseif tf == 'number' then
        return f == s or options.nonumber
      else
        -- assume they're the same functions/userdata/looped-table
        -- type matching before would already cover it otherwise
        return true
      end
    end)
  end

  -- inspect+serialize both tables, to normalize them, separate their
  -- metatables, limit depth, etc.  Also, since we pass the filter option on,
  -- the filtered items become "<filtered>" and will by definition match
  local function normalizeTable(t)
    return assert( inspect.marshal( inspect.inspect(t,{serialize=true,depth=depth,filter=filter}), {nometa=options.nometa} ))
  end

  local first = normalizeTable(firstTable)
  local second = normalizeTable(secondTable)

  return checkTable(first, second, {}), first

end

-------------------------------------------------------------------



-------------------------------------------------------------------
-- Given a table of key strings, return a function that can be used for
-- the 'filter' option of inspect() and inspect.compare() functions.
function inspect.makeFilter(arrayTable)
  local filter = {} -- our filter lookup tree (tables of tables)
  local matchNode = {} -- a table instance we use as a key for nodes which match
  local wildcard = {} -- a key table of wildcard match names

  local function buildFilter(pathname)
    local t = filter
    local key
    -- if the filtered name starts with a '.', it's a wildcard
    if pathname:find("^%.") then
      wildcard[pathname:sub(2)] = true
      return
    end
    for sep, name in pathname:gmatch("([%.%[\"\']*)([^%.%[\"\'%]]+)[\"\'%]]?") do
      if sep == '[' then
        if name == 'true' then
          key = true
        elseif name == 'false' then
          key = false
        else
          key = tonumber(name)
        end
      else
        -- to be safe, we'll check the key name doesn't mean a table/function/userdata
        local tn = getType(name)
        if tn == 'string' then
          key = name
        else
          error("filter key '"..pathname.."' has key '"..name.."' which is an unsupported type ("..tn..")")
        end
      end

      if not t[key] then
        t[key] = {}
      end
      t = t[key]
    end

    t[matchNode] = true
  end

  -- we could call serializePath() and do a simple lookup, but it's expensive and
  -- we'd be calling it a LOT.  So instead we break up the filter
  -- table into true "path" elements, into a filter tree, and compare
  -- against it... thereby avoiding string concat/manip during compare.

  for _, pathname in ipairs(arrayTable) do
    buildFilter(pathname)
  end

  return function(value,path)
      local t = filter
      if wildcard[ path[#path] ] then
        return true
      end
      for _,v in ipairs(path) do
          if not t[v] then
            return false
          end
          t = t[v]
      end
      return t[matchNode] == true
    end

end

return inspect

