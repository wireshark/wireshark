-- See Copyright Notice in the file lrexlib.h

local luatest = require "luatest"
local N = luatest.NT

local function norm(a) return a==nil and N or a end

local function fill (n, m)
  local t = {}
  for i = n, m, -1 do table.insert (t, i) end
  return t
end

local function set_named_subpatterns (lib, flg)
  return {
    Name = "Named Subpatterns",
    Func = function (subj, methodname, patt, name1, name2)
      local r = lib.new (patt)
      local _,_,caps = r[methodname] (r, subj)
      return norm(caps[name1]), norm(caps[name2])
    end,
    --{} N.B. subject is always first element
    { {"abcd", "tfind", "(?P<dog>.)b.(?P<cat>d)", "dog", "cat"},  {"a","d"} },
    { {"abcd", "exec",  "(?P<dog>.)b.(?P<cat>d)", "dog", "cat"},  {"a","d"} },
  }
end

local function set_f_find (lib, flg)
  local cp1251 =
    "¿¡¬√ƒ≈®∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ‹€⁄›ﬁﬂ‡·‚„‰Â∏ÊÁËÈÍÎÏÌÓÔÒÚÛÙıˆ˜¯˘¸˚˙˝˛ˇ"
  local loc = "Russian_Russia.1251"
  return {
  Name = "Function find",
  Func = lib.find,
  --{subj,   patt,      st,cf,ef,lo},        { results }
  { {"abcd", ".+",      5},                  { N   } }, -- failing st
  { {"abcd", ".*?"},                         { 1,0 } }, -- non-greedy
  { {"abc",  "aBC",     N,flg.CASELESS},     { 1,3 } }, -- cf
  { {"abc",  "aBC",     N,"i"         },     { 1,3 } }, -- cf
  { {"abc",  "bc",      N,flg.ANCHORED},     { N   } }, -- cf
  { {"abc",  "bc",      N,N,flg.ANCHORED},   { N   } }, -- ef
--{ {cp1251, "[[:upper:]]+", N,N,N, loc},    { 1,33} }, -- locale
--{ {cp1251, "[[:lower:]]+", N,N,N, loc},    {34,66} }, -- locale
}
end

local function set_f_match (lib, flg)
  return {
  Name = "Function match",
  Func = lib.match,
  --{subj,   patt,      st,cf,ef,lo},        { results }
  { {"abcd", ".+",      5},                  { N    }}, -- failing st
  { {"abcd", ".*?"},                         { ""   }}, -- non-greedy
  { {"abc",  "aBC",     N,flg.CASELESS},     {"abc" }}, -- cf
  { {"abc",  "aBC",     N,"i"         },     {"abc" }}, -- cf
  { {"abc",  "bc",      N,flg.ANCHORED},     { N    }}, -- cf
  { {"abc",  "bc",      N,N,flg.ANCHORED},   { N    }}, -- ef
}
end

local function set_f_gmatch (lib, flg)
  -- gmatch (s, p, [cf], [ef])
  local pCSV = "(^[^,]*)|,([^,]*)"
  local F = false
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
  --{  subj             patt   results }
    { {"a\0c",          "." }, {{"a",N},{"\0",N},{"c",N}} },--nuls in subj
    { {"",              pCSV}, {{"",F}} },
    { {"12",            pCSV}, {{"12",F}} },
    { {",",             pCSV}, {{"", F},{F,""}} },
    { {"12,,45",        pCSV}, {{"12",F},{F,""},{F,"45"}} },
    { {",,12,45,,ab,",  pCSV}, {{"",F},{F,""},{F,"12"},{F,"45"},{F,""},{F,"ab"},{F,""}} },
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
    { {"a,\0,c",       ","},     {{"a",",",N},{"\0",",",N},{"c",N,N},   } },--nuls in subj
    { {"ab",           "$"},     {{"ab","",N}, {"",N,N},               } },
    { {"ab",         "^|$"},     {{"", "", N}, {"ab","",N},  {"",N,N}, } },
    { {"ab45ab","(?<=ab).*?"},   {{"ab","",N}, {"45ab","",N},{"",N,N}, } },
    { {"ab",         "\\b"},     {{"", "", N}, {"ab","",N},  {"",N,N}, } },
  }
end

local function set_m_exec (lib, flg)
  return {
  Name = "Method exec",
  Method = "exec",
--{patt,cf,lo},           {subj,st,ef}              { results }
  { {".+"},               {"abcd",5},               { N }    }, -- failing st
  { {".*?"},              {"abcd"},                 {1,0,{}} }, -- non-greedy
  { {"aBC",flg.CASELESS}, {"abc"},                  {1,3,{}} }, -- cf
  { {"aBC","i"         }, {"abc"},                  {1,3,{}} }, -- cf
  { {"bc",flg.ANCHORED},  {"abc"},                  { N }    }, -- cf
  { {"bc"},               {"abc",N, flg.ANCHORED},  { N }    }, -- ef
}
end

local function set_m_tfind (lib, flg)
  return {
  Name = "Method tfind",
  Method = "tfind",
--{patt,cf,lo},           {subj,st,ef}              { results }
  { {".+"},               {"abcd",5},               { N }    }, -- failing st
  { {".*?"},              {"abcd"},                 {1,0,{}} }, -- non-greedy
  { {"aBC",flg.CASELESS}, {"abc"},                  {1,3,{}} }, -- cf
  { {"aBC","i"         }, {"abc"},                  {1,3,{}} }, -- cf
  { {"bc",flg.ANCHORED},  {"abc"},                  { N }    }, -- cf
  { {"bc"},               {"abc",N, flg.ANCHORED},  { N }    }, -- ef
}
end

local function set_m_dfa_exec (lib, flg)
  return {
  Name = "Method dfa_exec",
  Method = "dfa_exec",
--{patt,cf,lo},           {subj,st,ef,os,ws}        { results }
  { {".+"},               {"abcd"},                 {1,{4,3,2,1},4} }, -- [none]
  { {".+"},               {"abcd",2},               {2,{4,3,2},  3} }, -- positive st
  { {".+"},               {"abcd",-2},              {3,{4,3},    2} }, -- negative st
  { {".+"},               {"abcd",5},               {N }            }, -- failing st
  { {".*"},               {"abcd"},                 {1,{4,3,2,1,0},5}}, -- [none]
  { {".*?"},              {"abcd"},                 {1,{4,3,2,1,0},5}}, -- non-greedy
  { {"aBC",flg.CASELESS}, {"abc"},                  {1,{3},1}  }, -- cf
  { {"aBC","i"         }, {"abc"},                  {1,{3},1}  }, -- cf
  { {"bc"},               {"abc"},                  {2,{3},1}  }, -- [none]
  { {"bc",flg.ANCHORED},  {"abc"},                  {N }       }, -- cf
  { {"bc"},               {"abc",N, flg.ANCHORED},  {N }       }, -- ef
  { { "(.)b.(d)"},        {"abcd"},                 {1,{4},1}  }, --[captures]
  { {"abc"},              {"ab"},                   {N }       },
  { {"abc"},              {"ab",N,flg.PARTIAL},     {1,{2},flg.ERROR_PARTIAL} },
  { {".+"},     {string.rep("a",50),N,N,50,50},     {1, fill(50,26), 0}},-- small ovecsize
}
end

return function (libname, isglobal)
  local lib = isglobal and _G[libname] or require (libname)
  local flags = lib.flags ()
  local sets = {
    set_f_match  (lib, flags),
    set_f_find   (lib, flags),
    set_f_gmatch (lib, flags),
    set_f_split  (lib, flags),
    set_m_exec   (lib, flags),
    set_m_tfind  (lib, flags),
  }
  if flags.MAJOR >= 4 then
    table.insert (sets, set_named_subpatterns (lib, flags))
  end
  if flags.MAJOR >= 6 then
    table.insert (sets, set_m_dfa_exec (lib, flags))
  end
  return sets
end
