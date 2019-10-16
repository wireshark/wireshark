-- See Copyright Notice in the file lrexlib.h

-- Convert Lua regex pattern to its PCRE equivalent.

local t_esc = {
  a = "[:alpha:]",
  A = "[:^alpha:]",
  c = "[:cntrl:]",
  C = "[:^cntrl:]",
  d = "[:digit:]",
  D = "[:^digit:]",
  l = "[:lower:]",
  L = "[:^lower:]",
  p = "[:punct:]",
  P = "[:^punct:]",
  s = "[:space:]",
  S = "[:^space:]",
  u = "[:upper:]",
  U = "[:^upper:]",
  w = "[:alnum:]",
  W = "[:^alnum:]",
  x = "[:xdigit:]",
  X = "[:^xdigit:]",
  z = "\\x00",
  Z = "\\x01-\\xFF",
}

local function rep_normal (ch)
  assert (ch ~= "b", "\"%b\" subpattern is not supported")
  assert (ch ~= "0", "invalid capture index")
  local v = t_esc[ch]
  return v and ("[" .. v .. "]") or ("\\" .. ch)
end

local function rep_charclass (ch)
  return t_esc[ch] or ("\\" .. ch)
end

function pat2pcre (s)
  local ind = 0

  local function getc ()
    ind = ind + 1
    return string.sub (s, ind, ind)
  end

  local function getnum ()
    local num = string.match (s, "^\\(%d%d?%d?)", ind)
    if num then
      ind = ind + #num
      return string.format ("\\x%02X", num)
    end
  end

  local out, state = "", "normal"
  while ind < #s do
    local ch = getc ()
    if state == "normal" then
      if ch == "%" then
        out = out .. rep_normal (getc ())
      elseif ch == "-" then
        out = out .. "*?"
      elseif ch == "." then
        out = out .. "\\C"
      elseif ch == "[" then
        out = out .. ch
        state = "charclass"
      else
        local num = getnum ()
        out = num and (out .. num) or (out .. ch)
      end
    elseif state == "charclass" then
      if ch == "%" then
        out = out .. rep_charclass (getc ())
      elseif ch == "]" then
        out = out .. ch
        state = "normal"
      else
        local num = getnum ()
        out = num and (out .. num) or (out .. ch)
      end
    end
  end
  return out
end

return pat2pcre
