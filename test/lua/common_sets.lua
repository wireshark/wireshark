-- See Copyright Notice in the file LICENSE

-- This file should contain only test sets that behave identically
-- when being run with pcre or posix regex libraries.

local luatest = require "luatest"
local N = luatest.NT

local function norm(a) return a==nil and N or a end

local function get_gsub (lib)
  return lib.gsub or
    function (subj, pattern, repl, n)
      return lib.new (pattern) : gsub (subj, repl, n)
    end
end

local function set_f_gmatch (lib, flg)
  -- gmatch (s, p, [cf], [ef])
  local function test_gmatch (subj, patt)
    local out, guard = {}, 10
    for a, b in lib.gmatch (subj, patt) do
      table.insert (out, { norm(a), norm(b) })
      guard = guard - 1
      if guard == 0 then break end
    end
    return unpack (out)
  end
  return {
    Name = "Function gmatch",
    Func = test_gmatch,
  --{  subj             patt         results }
    { {"ab",            lib.new"."}, {{"a",N}, {"b",N} } },
    { {("abcd"):rep(3), "(.)b.(d)"}, {{"a","d"},{"a","d"},{"a","d"}} },
    { {"abcd",          ".*" },      {{"abcd",N},{"",N}  } },--zero-length match
    { {"abc",           "^." },      {{"a",N}} },--anchored pattern
  }
end

local function set_f_split (lib, flg)
  -- split (s, p, [cf], [ef])
  local function test_split (subj, patt)
    local out, guard = {}, 10
    for a, b, c in lib.split (subj, patt) do
      table.insert (out, { norm(a), norm(b), norm(c) })
      guard = guard - 1
      if guard == 0 then break end
    end
    return unpack (out)
  end
  return {
    Name = "Function split",
    Func = test_split,
  --{  subj             patt      results }
    { {"ab",     lib.new","},     {{"ab",N,N},                           } },
    { {"ab",            ","},     {{"ab",N,N},                           } },
    { {",",             ","},     {{"",",",N},     {"", N, N},           } },
    { {",,",            ","},     {{"",",",N},     {"",",",N},  {"",N,N} } },
    { {"a,b",           ","},     {{"a",",",N},    {"b",N,N},            } },
    { {",a,b",          ","},     {{"",",",N},     {"a",",",N}, {"b",N,N}} },
    { {"a,b,",          ","},     {{"a",",",N},    {"b",",",N}, {"",N,N} } },
    { {"a,,b",          ","},     {{"a",",",N},    {"",",",N},  {"b",N,N}} },
    { {"ab<78>c", "<(.)(.)>"},    {{"ab","7","8"}, {"c",N,N},            } },
    { {"abc",          "^."},     {{"", "a",N},    {"bc",N,N},           } },--anchored pattern
    { {"abc",           "^"},     {{"", "", N},    {"abc",N,N},          } },
--  { {"abc",           "$"},     {{"abc","",N},   {"",N,N},             } },
--  { {"abc",         "^|$"},     {{"", "", N},    {"abc","",N},{"",N,N},} },
  }
end

local function set_f_find (lib, flg)
  return {
    Name = "Function find",
    Func = lib.find,
  --  {subj, patt, st},         { results }
    { {"abcd", lib.new".+"},    { 1,4 }   },      -- [none]
    { {"abcd", ".+"},           { 1,4 }   },      -- [none]
    { {"abcd", ".+", 2},        { 2,4 }   },      -- positive st
    { {"abcd", ".+", -2},       { 3,4 }   },      -- negative st
    { {"abcd", ".*"},           { 1,4 }   },      -- [none]
    { {"abc",  "bc"},           { 2,3 }   },      -- [none]
    { {"abcd", "(.)b.(d)"},     { 1,4,"a","d" }}, -- [captures]
  }
end

local function set_f_match (lib, flg)
  return {
    Name = "Function match",
    Func = lib.match,
  --  {subj, patt, st},         { results }
    { {"abcd", lib.new".+"},    {"abcd"}  }, -- [none]
    { {"abcd", ".+"},           {"abcd"}  }, -- [none]
    { {"abcd", ".+", 2},        {"bcd"}   }, -- positive st
    { {"abcd", ".+", -2},       {"cd"}    }, -- negative st
    { {"abcd", ".*"},           {"abcd"}  }, -- [none]
    { {"abc",  "bc"},           {"bc"}    }, -- [none]
    { {"abcd", "(.)b.(d)"},     {"a","d"} }, -- [captures]
  }
end

local function set_m_exec (lib, flg)
  return {
    Name = "Method exec",
    Method = "exec",
  --{patt},                 {subj, st}           { results }
    { {".+"},               {"abcd"},            {1,4,{}}  }, -- [none]
    { {".+"},               {"abcd",2},          {2,4,{}}  }, -- positive st
    { {".+"},               {"abcd",-2},         {3,4,{}}  }, -- negative st
    { {".*"},               {"abcd"},            {1,4,{}}  }, -- [none]
    { {"bc"},               {"abc"},             {2,3,{}}  }, -- [none]
    { { "(.)b.(d)"},        {"abcd"},            {1,4,{1,1,4,4}}},--[captures]
    { {"(a+)6+(b+)"},       {"Taa66bbT",2},      {2,7,{2,3,6,7}}},--[st+captures]
  }
end

local function set_m_tfind (lib, flg)
  return {
    Name = "Method tfind",
    Method = "tfind",
  --{patt},                 {subj, st}           { results }
    { {".+"},               {"abcd"},            {1,4,{}}  }, -- [none]
    { {".+"},               {"abcd",2},          {2,4,{}}  }, -- positive st
    { {".+"},               {"abcd",-2},         {3,4,{}}  }, -- negative st
    { {".*"},               {"abcd"},            {1,4,{}}  }, -- [none]
    { {"bc"},               {"abc"},             {2,3,{}}  }, -- [none]
    { {"(.)b.(d)"},         {"abcd"},            {1,4,{"a","d"}}},--[captures]
  }
end

local function set_m_find (lib, flg)
  return {
    Name = "Method find",
    Method = "find",
  --{patt},                 {subj, st}           { results }
    { {".+"},               {"abcd"},            {1,4}  }, -- [none]
    { {".+"},               {"abcd",2},          {2,4}  }, -- positive st
    { {".+"},               {"abcd",-2},         {3,4}  }, -- negative st
    { {".*"},               {"abcd"},            {1,4}  }, -- [none]
    { {"bc"},               {"abc"},             {2,3}  }, -- [none]
    { {"(.)b.(d)"},         {"abcd"},            {1,4,"a","d"}},--[captures]
  }
end

local function set_m_match (lib, flg)
  return {
    Name = "Method match",
    Method = "match",
  --{patt},                 {subj, st}           { results }
    { {".+"},               {"abcd"},            {"abcd"}  }, -- [none]
    { {".+"},               {"abcd",2},          {"bcd" }  }, -- positive st
    { {".+"},               {"abcd",-2},         {"cd"  }  }, -- negative st
    { {".*"},               {"abcd"},            {"abcd"}  }, -- [none]
    { {"bc"},               {"abc"},             {"bc"  }  }, -- [none]
    {{ "(.)b.(d)"},         {"abcd"},            {"a","d"} }, --[captures]
  }
end

local function set_f_gsub1 (lib, flg)
  local subj, pat = "abcdef", "[abef]+"
  local cpat = lib.new(pat)
  return {
    Name = "Function gsub, set1",
    Func = get_gsub (lib),
  --{ s,       p,    f,   n,    res1,  res2, res3 },
    { {subj,  cpat,  "",  0},   {subj,    0, 0} }, -- test "n" + empty_replace
    { {subj,   pat,  "",  0},   {subj,    0, 0} }, -- test "n" + empty_replace
    { {subj,   pat,  "", -1},   {subj,    0, 0} }, -- test "n" + empty_replace
    { {subj,   pat,  "",  1},   {"cdef",  1, 1} },
    { {subj,   pat,  "",  2},   {"cd",    2, 2} },
    { {subj,   pat,  "",  3},   {"cd",    2, 2} },
    { {subj,   pat,  ""    },   {"cd",    2, 2} },
    { {subj,   pat,  "#", 0},   {subj,    0, 0} }, -- test "n" + non-empty_replace
    { {subj,   pat,  "#", 1},   {"#cdef", 1, 1} },
    { {subj,   pat,  "#", 2},   {"#cd#",  2, 2} },
    { {subj,   pat,  "#", 3},   {"#cd#",  2, 2} },
    { {subj,   pat,  "#"   },   {"#cd#",  2, 2} },
    { {"abc",  "^.", "#"   },   {"#bc",   1, 1} }, -- anchored pattern
  }
end

local function set_f_gsub2 (lib, flg)
  local subj, pat = "abc", "([ac])"
  return {
    Name = "Function gsub, set2",
    Func = get_gsub (lib),
  --{ s,     p,   f,   n,     res1,    res2, res3 },
    { {subj, pat, "<%1>" },   {"<a>b<c>", 2, 2} }, -- test non-escaped chars in f
    { {subj, pat, "%<%1%>" }, {"<a>b<c>", 2, 2} }, -- test escaped chars in f
    { {subj, pat, "" },       {"b",       2, 2} }, -- test empty replace
    { {subj, pat, "1" },      {"1b1",     2, 2} }, -- test odd and even %'s in f
    { {subj, pat, "%1" },     {"abc",     2, 2} },
    { {subj, pat, "%%1" },    {"%1b%1",   2, 2} },
    { {subj, pat, "%%%1" },   {"%ab%c",   2, 2} },
    { {subj, pat, "%%%%1" },  {"%%1b%%1", 2, 2} },
    { {subj, pat, "%%%%%1" }, {"%%ab%%c", 2, 2} },
  }
end

local function set_f_gsub3 (lib, flg)
  return {
    Name = "Function gsub, set3",
    Func = get_gsub (lib),
  --{ s,      p,      f,  n,   res1,res2,res3 },
    { {"abc", "a",    "%0" }, {"abc", 1, 1} }, -- test (in)valid capture index
    { {"abc", "a",    "%1" }, {"abc", 1, 1} },
    { {"abc", "[ac]", "%1" }, {"abc", 2, 2} },
    { {"abc", "(a)",  "%1" }, {"abc", 1, 1} },
    { {"abc", "(a)",  "%2" }, "invalid capture index" },
  }
end

local function set_f_gsub4 (lib, flg)
  return {
    Name = "Function gsub, set4",
    Func = get_gsub (lib),
  --{ s,           p,              f, n,  res1,      res2, res3 },
    { {"a2c3",     ".",            "#" }, {"####",      4, 4} }, -- test .
    { {"a2c3",     ".+",           "#" }, {"#",         1, 1} }, -- test .+
    { {"a2c3",     ".*",           "#" }, {"##",        2, 2} }, -- test .*
    { {"/* */ */", "\\/\\*(.*)\\*\\/", "#" }, {"#",     1, 1} },
    { {"a2c3",     "[0-9]",        "#" }, {"a#c#",      2, 2} }, -- test %d
    { {"a2c3",     "[^0-9]",       "#" }, {"#2#3",      2, 2} }, -- test %D
    { {"a \t\nb",  "[ \t\n]",      "#" }, {"a###b",     3, 3} }, -- test %s
    { {"a \t\nb",  "[^ \t\n]",     "#" }, {"# \t\n#",   2, 2} }, -- test %S
  }
end

local function set_f_gsub5 (lib, flg)
  local function frep1 () end                       -- returns nothing
  local function frep2 () return "#" end            -- ignores arguments
  local function frep3 (...) return table.concat({...}, ",") end -- "normal"
  local function frep4 () return {} end             -- invalid return type
  local function frep5 () return "7", "a" end       -- 2-nd return is "a"
  local function frep6 () return "7", "break" end   -- 2-nd return is "break"
  local subj = "a2c3"
  return {
    Name = "Function gsub, set5",
    Func = get_gsub (lib),
  --{ s,     p,          f,   n,   res1,     res2, res3 },
    { {subj, "a(.)c(.)", frep1 }, {subj,        1, 0} },
    { {subj, "a(.)c(.)", frep2 }, {"#",         1, 1} },
    { {subj, "a(.)c(.)", frep3 }, {"2,3",       1, 1} },
    { {subj, "a.c.",     frep3 }, {subj,        1, 1} },
    { {subj, "z*",       frep1 }, {subj,        5, 0} },
    { {subj, "z*",       frep2 }, {"#a#2#c#3#", 5, 5} },
    { {subj, "z*",       frep3 }, {subj,        5, 5} },
    { {subj, subj,       frep4 }, "invalid return type" },
    { {"abc",".",        frep5 }, {"777",       3, 3} },
    { {"abc",".",        frep6 }, {"777",       3, 3} },
  }
end

local function set_f_gsub6 (lib, flg)
  local tab1, tab2, tab3 = {}, { ["2"] = 56 }, { ["2"] = {} }
  local subj = "a2c3"
  return {
    Name = "Function gsub, set6",
    Func = get_gsub (lib),
  --{ s,     p,          f, n,   res1,res2,res3 },
    { {subj, "a(.)c(.)", tab1 }, {subj,  1, 0} },
    { {subj, "a(.)c(.)", tab2 }, {"56",  1, 1} },
    { {subj, "a(.)c(.)", tab3 }, "invalid replacement type" },
    { {subj, "a.c.",     tab1 }, {subj,  1, 0} },
    { {subj, "a.c.",     tab2 }, {subj,  1, 0} },
    { {subj, "a.c.",     tab3 }, {subj,  1, 0} },
  }
end

local function set_f_gsub8 (lib, flg)
  local subj, patt, repl = "abcdef", "..", "*"
  return {
    Name = "Function gsub, set8",
    Func = get_gsub (lib),
  --{ s,     p,       f, n,                                    res1,  res2, res3 },
    { {subj, patt, repl, function() end },                    {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return nil end },         {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return false end },       {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return true end },        {"***",    3, 3} },
    { {subj, patt, repl, function() return {} end },          {"***",    3, 3} },
    { {subj, patt, repl, function() return "#" end },         {"###",    3, 3} },
    { {subj, patt, repl, function() return 57 end },          {"575757", 3, 3} },
    { {subj, patt, repl, function (from) return from end },   {"135",    3, 3} },
    { {subj, patt, repl, function (from, to) return to end }, {"246",    3, 3} },
    { {subj, patt, repl, function (from,to,rep) return rep end },
                                                              {"***",    3, 3} },
    { {subj, patt, repl, function (from, to, rep) return rep..to..from end },
                                                           {"*21*43*65", 3, 3} },
    { {subj, patt, repl, function() return nil end },         {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return nil, nil end },    {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return nil, false end },  {"abcdef", 3, 0} },
    { {subj, patt, repl, function() return nil, true end },   {"ab**",   3, 2} },
    { {subj, patt, repl, function() return true, true end },  {"***",    3, 3} },
    { {subj, patt, repl, function() return nil, 0 end },      {"abcdef", 1, 0} },
    { {subj, patt, repl, function() return true, 0 end },     {"*cdef",  1, 1} },
    { {subj, patt, repl, function() return nil, 1 end },      {"ab*ef",  2, 1} },
    { {subj, patt, repl, function() return true, 1 end },     {"**ef",   2, 2} },
  }
end

return function (libname, isglobal)
  local lib = isglobal and _G[libname] or require (libname)
  return {
    set_f_gmatch    (lib),
    set_f_split     (lib),
    set_f_find      (lib),
    set_f_match     (lib),
    set_m_exec      (lib),
    set_m_tfind     (lib),
    set_m_find      (lib),
    set_m_match     (lib),
    set_f_gsub1     (lib),
    set_f_gsub2     (lib),
    set_f_gsub3     (lib),
    set_f_gsub4     (lib),
    set_f_gsub5     (lib),
    set_f_gsub6     (lib),
    set_f_gsub8     (lib),
  }
end
