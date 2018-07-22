-- See Copyright Notice in the file LICENSE

local pat2pcre = require "pat2pcre"

local function get_gsub (lib)
  return lib.gsub or
    function (subj, pattern, repl, n)
      return lib.new (pattern) : gsub (subj, repl, n)
    end
end

local function set_f_gsub1 (lib, flg)
  local subj, pat = "abcdef", "[abef]+"
  return {
    Name = "Function gsub, set1",
    Func = get_gsub (lib),
  --{ s,       p,    f,   n,    res1,  res2, res3 },
    { {"a\0c", ".",  "#"   },   {"###",   3, 3} }, -- subj contains nuls
  }
end

local function set_f_gsub4 (lib, flg)
  local pCSV = "(^[^,]*)|,([^,]*)"
  local fCSV = function (a,b) return "["..(a or b).."]" end
  local set = {
    Name = "Function gsub, set4",
    Func = get_gsub (lib),
  --{ s,           p,              f, n,  res1,      res2, res3 },
    { {"/* */ */", "%/%*(.*)%*%/", "#" }, {"#",         1, 1} },
    { {"a2c3",     ".-",           "#" }, {"#########", 9, 9} }, -- test .-
    { {"/**/",     "%/%*(.-)%*%/", "#" }, {"#",         1, 1} },
    { {"/* */ */", "%/%*(.-)%*%/", "#" }, {"# */",      1, 1} },
    { {"a2c3",     "%d",           "#" }, {"a#c#",      2, 2} }, -- test %d
    { {"a2c3",     "%D",           "#" }, {"#2#3",      2, 2} }, -- test %D
    { {"a \t\nb",  "%s",           "#" }, {"a###b",     3, 3} }, -- test %s
    { {"a \t\nb",  "%S",           "#" }, {"# \t\n#",   2, 2} }, -- test %S
    { {"abcd",     "\\b",          "%1"}, {"abcd",      2, 2} },
    { {"",                    pCSV,fCSV}, {"[]",        1, 1} },
    { {"123",                 pCSV,fCSV}, {"[123]",     1, 1} },
    { {",",                   pCSV,fCSV}, {"[][]",      2, 2} },
    { {"123,,456",            pCSV,fCSV}, {"[123][][456]", 3, 3}},
    { {",,123,456,,abc,789,", pCSV,fCSV}, {"[][][123][456][][abc][789][]", 8, 8}},
  }
  -- convert patterns: lua -> pcre
  for _, test in ipairs (set) do
    test[1][2] = pat2pcre (test[1][2])
  end
  return set
end

local function set_f_gsub7 (lib, flg)
  local subj = ""
  for i = 0, 255 do
    subj = subj .. string.char (i)
  end

  -- This set requires calling prepare_set before calling gsub_test
  local set = {
    Name = "Function gsub, set7",
    Func = get_gsub (lib),
  --{ s,     p,    f, n, },
    { {subj, "%a", "" }, },
    { {subj, "%A", "" }, },
    { {subj, "%c", "" }, },
    { {subj, "%C", "" }, },
    { {subj, "%l", "" }, },
    { {subj, "%L", "" }, },
    { {subj, "%p", "" }, },
    { {subj, "%P", "" }, },
    { {subj, "%u", "" }, },
    { {subj, "%U", "" }, },
    { {subj, "%w", "" }, },
    { {subj, "%W", "" }, },
    { {subj, "%x", "" }, },
    { {subj, "%X", "" }, },
    { {subj, "%z", "" }, },
    { {subj, "%Z", "" }, },

    { {subj, "[%a]", "" }, },
    { {subj, "[%A]", "" }, },
    { {subj, "[%c]", "" }, },
    { {subj, "[%C]", "" }, },
    { {subj, "[%l]", "" }, },
    { {subj, "[%L]", "" }, },
    { {subj, "[%p]", "" }, },
    { {subj, "[%P]", "" }, },
    { {subj, "[%u]", "" }, },
    { {subj, "[%U]", "" }, },
    { {subj, "[%w]", "" }, },
    { {subj, "[%W]", "" }, },
    { {subj, "[%x]", "" }, },
    { {subj, "[%X]", "" }, },
    { {subj, "[%z]", "" }, },
    { {subj, "[%Z]", "" }, },

    { {subj, "[%a_]", "" }, },
    { {subj, "[%A_]", "" }, },
    { {subj, "[%c_]", "" }, },
    { {subj, "[%C_]", "" }, },
    { {subj, "[%l_]", "" }, },
    { {subj, "[%L_]", "" }, },
    { {subj, "[%p_]", "" }, },
    { {subj, "[%P_]", "" }, },
    { {subj, "[%u_]", "" }, },
    { {subj, "[%U_]", "" }, },
    { {subj, "[%w_]", "" }, },
    { {subj, "[%W_]", "" }, },
    { {subj, "[%x_]", "" }, },
    { {subj, "[%X_]", "" }, },
    { {subj, "[%z_]", "" }, },
    { {subj, "[%Z_]", "" }, },

    { {subj, "[%a%d]", "" }, },
    { {subj, "[%A%d]", "" }, },
    { {subj, "[%c%d]", "" }, },
    { {subj, "[%C%d]", "" }, },
    { {subj, "[%l%d]", "" }, },
    { {subj, "[%L%d]", "" }, },
    { {subj, "[%p%d]", "" }, },
    { {subj, "[%P%d]", "" }, },
    { {subj, "[%u%d]", "" }, },
    { {subj, "[%U%d]", "" }, },
    { {subj, "[%w%d]", "" }, },
    { {subj, "[%W%d]", "" }, },
    { {subj, "[%x%d]", "" }, },
    { {subj, "[%X%d]", "" }, },
    { {subj, "[%z%d]", "" }, },
    { {subj, "[%Z%d]", "" }, },

    { {subj, "[^%a%d]", "" }, },
    { {subj, "[^%A%d]", "" }, },
    { {subj, "[^%c%d]", "" }, },
    { {subj, "[^%C%d]", "" }, },
    { {subj, "[^%l%d]", "" }, },
    { {subj, "[^%L%d]", "" }, },
    { {subj, "[^%p%d]", "" }, },
    { {subj, "[^%P%d]", "" }, },
    { {subj, "[^%u%d]", "" }, },
    { {subj, "[^%U%d]", "" }, },
    { {subj, "[^%w%d]", "" }, },
    { {subj, "[^%W%d]", "" }, },
    { {subj, "[^%x%d]", "" }, },
    { {subj, "[^%X%d]", "" }, },
    { {subj, "[^%z%d]", "" }, },
    { {subj, "[^%Z%d]", "" }, },

    { {subj, "[^%a_]", "" }, },
    { {subj, "[^%A_]", "" }, },
    { {subj, "[^%c_]", "" }, },
    { {subj, "[^%C_]", "" }, },
    { {subj, "[^%l_]", "" }, },
    { {subj, "[^%L_]", "" }, },
    { {subj, "[^%p_]", "" }, },
    { {subj, "[^%P_]", "" }, },
    { {subj, "[^%u_]", "" }, },
    { {subj, "[^%U_]", "" }, },
    { {subj, "[^%w_]", "" }, },
    { {subj, "[^%W_]", "" }, },
    { {subj, "[^%x_]", "" }, },
    { {subj, "[^%X_]", "" }, },
    { {subj, "[^%z_]", "" }, },
    { {subj, "[^%Z_]", "" }, },

    { {subj, "\100",          "" }, },
    { {subj, "[\100]",        "" }, },
    { {subj, "[^\100]",       "" }, },
    { {subj, "[\100-\200]",   "" }, },
    { {subj, "[^\100-\200]",  "" }, },
    { {subj, "\100a",         "" }, },
    { {subj, "[\100a]",       "" }, },
    { {subj, "[^\100a]",      "" }, },
    { {subj, "[\100-\200a]",  "" }, },
    { {subj, "[^\100-\200a]", "" }, },
  }
  -- fill in reference results
  for _,v in ipairs(set) do
    local r0, r1, r2 = pcall (string.gsub, unpack (v[1]))
    v[2] = r0 and { r1, r2, r2 } or { r0, r1 }
  end
  -- convert patterns: lua -> pcre
  for _, test in ipairs (set) do
    test[1][2] = pat2pcre (test[1][2])
  end
  return set
end

return function (libname, isglobal)
  local lib = isglobal and _G[libname] or require (libname)
  local flags = lib.flags and lib.flags ()
  local sets = {
    set_f_gsub1 (lib, flags),
    set_f_gsub4 (lib, flags),
  }
  if flags.MAJOR*100 + flags.MINOR > 405 then
    table.insert (sets, set_f_gsub7 (lib, flags))
  end
  return sets
end
