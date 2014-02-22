-- See Copyright Notice in the file LICENSE

local pat2pcre = require "pat2pcre"
local luatest = require "luatest"
local N = luatest.NT

local function norm(a) return a==nil and N or a end

local function fill (n, m)
  local t = {}
  for i = n, m, -1 do table.insert (t, i) end
  return t
end


-- glib doesn't do partial matching return of matches, nor
-- does it support ovecsize being set through the API
local function set_m_dfa_exec (lib, flg)
  return {
  Name = "Method dfa_exec for glib",
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
  { {"abc"},              {"abc",N,flg.PARTIAL},    {1,{3},1}  },
  { {"abc*"},             {"abcc",N,flg.PARTIAL},   {1,{4,3,2},3} },
  { {"abc"},              {"ab",N,flg.PARTIAL},     {true} },
  { {"bc"},               {"ab",N,flg.PARTIAL},     {true} },
}
end

local function get_gsub (lib)
  return lib.gsub or
    function (subj, pattern, repl, n)
      return lib.new (pattern) : gsub (subj, repl, n)
    end
end

-- sadly, glib *always* sets the PCRE_UCP compilation flag, regardless
-- of REGEX_RAW being set - this is, frankly, a bug in my opinion
-- but anyway, it means things like '[:alpha:]' and '\w' match things that Lua's
-- '%a' does not match
local function set_f_gsub7 (lib, flg)
  local subj = ""
  for i = 0, 255 do
    subj = subj .. string.char (i)
  end

  -- This set requires calling prepare_set before calling gsub_test
  local set = {
    Name = "Function gsub, set7 for glib",
    Func = get_gsub (lib),
  --{ s,     p,    f, n, },
    { {subj, "[a-zA-Z]", "" }, },
    { {subj, "[^a-zA-Z]", "" }, },
    { {subj, "%c", "" }, },
    { {subj, "%C", "" }, },
    { {subj, "[a-z]", "" }, },
    { {subj, "[^a-z]", "" }, },
    { {subj, "%d", "" }, },
    { {subj, "%D", "" }, },
    { {subj, "%p", "" }, },
    { {subj, "%P", "" }, },
--  { {subj, "%s", "" }, },
--  { {subj, "%S", "" }, },
    { {subj, "[A-Z]", "" }, },
    { {subj, "[^A-Z]", "" }, }, -- 10
    { {subj, "[a-zA-Z0-9]", "" }, },
    { {subj, "[^a-zA-Z0-9]", "" }, },
    { {subj, "%x", "" }, },
    { {subj, "%X", "" }, },
    { {subj, "%z", "" }, },
    { {subj, "%Z", "" }, },

--  { {subj, "[%a]", "" }, },
--  { {subj, "[%A]", "" }, },
    { {subj, "[%c]", "" }, },
    { {subj, "[%C]", "" }, },
    { {subj, "[%d]", "" }, },
    { {subj, "[%D]", "" }, },
--  { {subj, "[%l]", "" }, },
--  { {subj, "[%L]", "" }, },
    { {subj, "[%p]", "" }, },
    { {subj, "[%P]", "" }, },
--  { {subj, "[%u]", "" }, },
--  { {subj, "[%U]", "" }, },
--  { {subj, "[%w]", "" }, },
--  { {subj, "[%W]", "" }, },
    { {subj, "[%x]", "" }, },
    { {subj, "[%X]", "" }, },
    { {subj, "[%z]", "" }, },
    { {subj, "[%Z]", "" }, },

--  { {subj, "[%a_]", "" }, },
--  { {subj, "[%A_]", "" }, },
    { {subj, "[%c_]", "" }, },
    { {subj, "[%C_]", "" }, },
--  { {subj, "[%l_]", "" }, },
--  { {subj, "[%L_]", "" }, },
    { {subj, "[%p_]", "" }, },
    { {subj, "[%P_]", "" }, },
--  { {subj, "[%u_]", "" }, },
--  { {subj, "[%U_]", "" }, },
--  { {subj, "[%w_]", "" }, },
--  { {subj, "[%W_]", "" }, },
    { {subj, "[%x_]", "" }, },
    { {subj, "[%X_]", "" }, },
    { {subj, "[%z_]", "" }, },
    { {subj, "[%Z_]", "" }, },

--  { {subj, "[%a%d]", "" }, },
--  { {subj, "[%A%d]", "" }, },
    { {subj, "[%c%d]", "" }, },
    { {subj, "[%C%d]", "" }, },
--  { {subj, "[%l%d]", "" }, },
--  { {subj, "[%L%d]", "" }, },
    { {subj, "[%p%d]", "" }, },
    { {subj, "[%P%d]", "" }, },
--  { {subj, "[%u%d]", "" }, },
--  { {subj, "[%U%d]", "" }, },
--  { {subj, "[%w%d]", "" }, },
--  { {subj, "[%W%d]", "" }, },
    { {subj, "[%x%d]", "" }, },
    { {subj, "[%X%d]", "" }, },
    { {subj, "[%z%d]", "" }, },
    { {subj, "[%Z%d]", "" }, },

--  { {subj, "[^%a%d]", "" }, },
--  { {subj, "[^%A%d]", "" }, },
    { {subj, "[^%c%d]", "" }, },
    { {subj, "[^%C%d]", "" }, },
--  { {subj, "[^%l%d]", "" }, },
--  { {subj, "[^%L%d]", "" }, },
    { {subj, "[^%p%d]", "" }, },
    { {subj, "[^%P%d]", "" }, },
--  { {subj, "[^%u%d]", "" }, },
--  { {subj, "[^%U%d]", "" }, },
--  { {subj, "[^%w%d]", "" }, },
--  { {subj, "[^%W%d]", "" }, },
    { {subj, "[^%x%d]", "" }, },
    { {subj, "[^%X%d]", "" }, },
    { {subj, "[^%z%d]", "" }, },
    { {subj, "[^%Z%d]", "" }, },

--  { {subj, "[^%a_]", "" }, },
--  { {subj, "[^%A_]", "" }, },
    { {subj, "[^%c_]", "" }, },
    { {subj, "[^%C_]", "" }, },
--  { {subj, "[^%l_]", "" }, },
--  { {subj, "[^%L_]", "" }, },
    { {subj, "[^%p_]", "" }, },
    { {subj, "[^%P_]", "" }, },
--  { {subj, "[^%u_]", "" }, },
--  { {subj, "[^%U_]", "" }, },
--  { {subj, "[^%w_]", "" }, },
--  { {subj, "[^%W_]", "" }, },
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
    set_m_dfa_exec (lib, flags),
    set_f_gsub7 (lib, flags)
  }
  return sets
end
