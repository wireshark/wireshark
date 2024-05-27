/* algo.h */
/*
 * Copyright (C) Reuben Thomas 2000-2020
 * Copyright (C) Shmuel Zeigerman 2004-2020

 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:

 * The above copyright notice and this permission notice shall
 * be included in all copies or substantial portions of the
 * Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "common.h"

#define REX_VERSION "Lrexlib " VERSION

/* Forward declarations */
static void gmatch_pushsubject (lua_State *L, TArgExec *argE);
static int findmatch_exec  (TUserdata *ud, TArgExec *argE);
static int split_exec      (TUserdata *ud, TArgExec *argE, int offset);
static int gsub_exec       (TUserdata *ud, TArgExec *argE, int offset);
static int gmatch_exec     (TUserdata *ud, TArgExec *argE);
static int compile_regex   (lua_State *L, const TArgComp *argC, TUserdata **pud);
static int generate_error  (lua_State *L, const TUserdata *ud, int errcode);

#define ALG_ENVIRONINDEX lua_upvalueindex(1)

#ifndef ALG_CHARSIZE
#  define ALG_CHARSIZE 1
#endif

#ifndef BUFFERZ_PUTREPSTRING
#  define BUFFERZ_PUTREPSTRING bufferZ_putrepstring
#endif

#ifndef ALG_GETCARGS
#  define ALG_GETCARGS(a,b,c)
#endif

#ifndef DO_NAMED_SUBPATTERNS
#define DO_NAMED_SUBPATTERNS(a,b,c)
#endif

#define METHOD_FIND  0
#define METHOD_MATCH 1
#define METHOD_EXEC  2
#define METHOD_TFIND 3


static int OptLimit (lua_State *L, int pos) {
  if (lua_isnoneornil (L, pos))
    return GSUB_UNLIMITED;
  if (lua_isfunction (L, pos))
    return GSUB_CONDITIONAL;
  if (lua_isnumber (L, pos)) {
    int a = lua_tointeger (L, pos);
    return a < 0 ? 0 : a;
  }
  return luaL_typerror (L, pos, "number or function");
}


static int get_startoffset(lua_State *L, int stackpos, size_t len) {
  int startoffset = (int)luaL_optinteger(L, stackpos, 1);
  if(startoffset > 0)
    startoffset--;
  else if(startoffset < 0) {
    startoffset += len/ALG_CHARSIZE;
    if(startoffset < 0)
      startoffset = 0;
  }
  return startoffset*ALG_CHARSIZE;
}


static TUserdata* test_ud (lua_State *L, int pos)
{
  TUserdata *ud;
  if (lua_getmetatable(L, pos) &&
      lua_rawequal(L, -1, ALG_ENVIRONINDEX) &&
      (ud = (TUserdata *)lua_touserdata(L, pos)) != NULL) {
    lua_pop(L, 1);
    return ud;
  }
  return NULL;
}


static TUserdata* check_ud (lua_State *L)
{
  TUserdata *ud = test_ud(L, 1);
  if (ud == NULL) luaL_typerror(L, 1, REX_TYPENAME);
  return ud;
}


static void check_subject (lua_State *L, int pos, TArgExec *argE)
{
  int stype;
  argE->text = lua_tolstring (L, pos, &argE->textlen);
  stype = lua_type (L, pos);
  if (stype != LUA_TSTRING && stype != LUA_TTABLE && stype != LUA_TUSERDATA) {
    luaL_typerror (L, pos, "string, table or userdata");
  } else if (argE->text == NULL) {
    int type;
    lua_getfield (L, pos, "topointer");
    if (lua_type (L, -1) != LUA_TFUNCTION)
      luaL_error (L, "subject has no topointer method");
    lua_pushvalue (L, pos);
    lua_call (L, 1, 1);
    type = lua_type (L, -1);
    if (type != LUA_TLIGHTUSERDATA)
      luaL_error (L, "subject's topointer method returned %s (expected lightuserdata)",
                  lua_typename (L, type));
    argE->text = (const char*) lua_touserdata (L, -1);
    lua_pop (L, 1);
    argE->textlen = luaL_len (L, pos);
  }
}

static void check_pattern (lua_State *L, int pos, TArgComp *argC)
{
  if (lua_isstring (L, pos)) {
    argC->pattern = lua_tolstring (L, pos, &argC->patlen);
    argC->ud = NULL;
  }
  else if ((argC->ud = test_ud (L, pos)) == NULL)
    luaL_typerror(L, pos, "string or " REX_TYPENAME);
}

static void checkarg_new (lua_State *L, TArgComp *argC) {
  argC->pattern = luaL_checklstring (L, 1, &argC->patlen);
  argC->cflags = ALG_GETCFLAGS (L, 2);
  ALG_GETCARGS (L, 3, argC);
}


/* function gsub (s, patt, f, [n], [cf], [ef], [larg...]) */
static void checkarg_gsub (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  lua_tostring (L, 3);    /* converts number (if any) to string */
  argE->reptype = lua_type (L, 3);
  if (argE->reptype != LUA_TSTRING && argE->reptype != LUA_TTABLE &&
      argE->reptype != LUA_TFUNCTION) {
    luaL_typerror (L, 3, "string, table or function");
  }
  argE->funcpos = 3;
  argE->funcpos2 = 4;
  argE->maxmatch = OptLimit (L, 4);
  argC->cflags = ALG_GETCFLAGS (L, 5);
  argE->eflags = (int)luaL_optinteger (L, 6, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 7, argC);
}


/* function count (s, patt, [cf], [ef], [larg...]) */
static void checkarg_count (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* function find  (s, patt, [st], [cf], [ef], [larg...]) */
/* function match (s, patt, [st], [cf], [ef], [larg...]) */
static void checkarg_find_func (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argC->cflags = ALG_GETCFLAGS (L, 4);
  argE->eflags = (int)luaL_optinteger (L, 5, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 6, argC);
}


/* function gmatch (s, patt, [cf], [ef], [larg...]) */
/* function split  (s, patt, [cf], [ef], [larg...]) */
static void checkarg_gmatch_split (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* method r:tfind (s, [st], [ef]) */
/* method r:exec  (s, [st], [ef]) */
/* method r:find  (s, [st], [ef]) */
/* method r:match (s, [st], [ef]) */
static void checkarg_find_method (lua_State *L, TArgExec *argE, TUserdata **ud) {
  *ud = check_ud (L);
  check_subject (L, 2, argE);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
}


static int algf_new (lua_State *L) {
  TArgComp argC;
  checkarg_new (L, &argC);
  return compile_regex (L, &argC, NULL);
}

static void push_substrings (lua_State *L, TUserdata *ud, const char *text,
                             TFreeList *freelist) {
  int i;
  if (lua_checkstack (L, ALG_NSUB(ud)) == 0) {
    if (freelist)
      freelist_free (freelist);
    luaL_error (L, "cannot add %d stack slots", ALG_NSUB(ud));
  }
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
  }
}

static int algf_gsub (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, n_subst = 0, st = 0, last_to = -1;
  TBuffer BufOut, BufRep, BufTemp, *pBuf = &BufOut;
  TFreeList freelist;
  /*------------------------------------------------------------------*/
  checkarg_gsub (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  freelist_init (&freelist);
  /*------------------------------------------------------------------*/
  if (argE.reptype == LUA_TSTRING) {
    buffer_init (&BufRep, 256, L, &freelist);
    BUFFERZ_PUTREPSTRING (&BufRep, argE.funcpos, ALG_NSUB(ud));
  }
  /*------------------------------------------------------------------*/
  if (argE.maxmatch == GSUB_CONDITIONAL) {
    buffer_init (&BufTemp, 1024, L, &freelist);
    pBuf = &BufTemp;
  }
  /*------------------------------------------------------------------*/
  buffer_init (&BufOut, 1024, L, &freelist);
  while ((argE.maxmatch < 0 || n_match < argE.maxmatch) && st <= (int)argE.textlen) {
    int from, to, res;
    int curr_subst = 0;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      freelist_free (&freelist);
      return generate_error (L, ud, res);
    }
    from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char (not replaced) */
        buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
    if (st < from) {
      buffer_addlstring (&BufOut, argE.text + st, from - st);
#ifdef ALG_PULL
      st = from;
#endif
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TSTRING) {
      size_t iter = 0, num;
      const char *str;
      while (bufferZ_next (&BufRep, &iter, &num, &str)) {
        if (str)
          buffer_addlstring (pBuf, str, num);
        else if (num == 0 || ALG_SUBVALID (ud,num))
          buffer_addlstring (pBuf, argE.text + ALG_BASE(st) + ALG_SUBBEG(ud,num), ALG_SUBLEN(ud,num));
      }
      curr_subst = 1;
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TTABLE) {
      if (ALG_NSUB(ud) > 0)
        ALG_PUSHSUB_OR_FALSE (L, ud, argE.text + ALG_BASE(st), 1);
      else
        lua_pushlstring (L, argE.text + from, to - from);
      lua_gettable (L, argE.funcpos);
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TFUNCTION) {
      int narg;
      lua_pushvalue (L, argE.funcpos);
      if (ALG_NSUB(ud) > 0) {
        push_substrings (L, ud, argE.text + ALG_BASE(st), &freelist);
        narg = ALG_NSUB(ud);
      }
      else {
        lua_pushlstring (L, argE.text + from, to - from);
        narg = 1;
      }
      if (0 != lua_pcall (L, narg, 1, 0)) {
        freelist_free (&freelist);
        return lua_error (L);  /* re-raise the error */
      }
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TTABLE || argE.reptype == LUA_TFUNCTION) {
      if (lua_tostring (L, -1)) {
        buffer_addvalue (pBuf, -1);
        curr_subst = 1;
      }
      else if (!lua_toboolean (L, -1))
        buffer_addlstring (pBuf, argE.text + from, to - from);
      else {
        freelist_free (&freelist);
        luaL_error (L, "invalid replacement value (a %s)", luaL_typename (L, -1));
      }
      if (argE.maxmatch != GSUB_CONDITIONAL)
        lua_pop (L, 1);
    }
    /*----------------------------------------------------------------*/
    if (argE.maxmatch == GSUB_CONDITIONAL) {
      /* Call the function */
      lua_pushvalue (L, argE.funcpos2);
      lua_pushinteger (L, from/ALG_CHARSIZE + 1);
      lua_pushinteger (L, to/ALG_CHARSIZE);
      if (argE.reptype == LUA_TSTRING)
        buffer_pushresult (&BufTemp);
      else {
        lua_pushvalue (L, -4);
        lua_remove (L, -5);
      }
      if (0 != lua_pcall (L, 3, 2, 0)) {
        freelist_free (&freelist);
        lua_error (L);  /* re-raise the error */
      }
      /* Handle the 1-st return value */
      if (lua_isstring (L, -2)) {               /* coercion is allowed here */
        buffer_addvalue (&BufOut, -2);          /* rep2 */
        curr_subst = 1;
      }
      else if (lua_toboolean (L, -2))
        buffer_addbuffer (&BufOut, &BufTemp);   /* rep1 */
      else {
        buffer_addlstring (&BufOut, argE.text + from, to - from); /* "no" */
        curr_subst = 0;
      }
      /* Handle the 2-nd return value */
      if (lua_type (L, -1) == LUA_TNUMBER) {    /* no coercion is allowed here */
        int n = lua_tointeger (L, -1);
        if (n < 0)                              /* n */
          n = 0;
        argE.maxmatch = n_match + n;
      }
      else if (lua_toboolean (L, -1))           /* "yes to all" */
        argE.maxmatch = GSUB_UNLIMITED;
      else
        buffer_clear (&BufTemp);

      lua_pop (L, 2);
      if (argE.maxmatch != GSUB_CONDITIONAL)
        pBuf = &BufOut;
    }
    /*----------------------------------------------------------------*/
    n_subst += curr_subst;
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  buffer_addlstring (&BufOut, argE.text + st, argE.textlen - st);
  buffer_pushresult (&BufOut);
  lua_pushinteger (L, n_match);
  lua_pushinteger (L, n_subst);
  freelist_free (&freelist);
  return 3;
}


static int algf_count (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, st = 0, last_to = -1;
  /*------------------------------------------------------------------*/
  checkarg_count (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  /*------------------------------------------------------------------*/
  while (st <= (int)argE.textlen) {
    int to, res;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      return generate_error (L, ud, res);
    }
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char */
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
#ifdef ALG_PULL
    {
      int from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
      if (st < from)
        st = from;
    }
#endif
    /*----------------------------------------------------------------*/
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  lua_pushinteger (L, n_match);
  return 1;
}


static int finish_generic_find (lua_State *L, TUserdata *ud, TArgExec *argE,
  int method, int res)
{
  if (ALG_ISMATCH (res)) {
    if (method == METHOD_FIND)
      ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE->startoffset), 0);
    if (ALG_NSUB(ud))    /* push captures */
      push_substrings (L, ud, argE->text, NULL);
    else if (method != METHOD_FIND) {
      ALG_PUSHSUB (L, ud, argE->text, 0);
      return 1;
    }
    return (method == METHOD_FIND) ? ALG_NSUB(ud) + 2 : ALG_NSUB(ud);
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error (L, ud, res);
}


static int generic_find_func (lua_State *L, int method) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int res;

  checkarg_find_func (L, &argC, &argE);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil (L), 1;

  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  res = findmatch_exec (ud, &argE);
  return finish_generic_find (L, ud, &argE, method, res);
}


static int algf_find (lua_State *L) {
  return generic_find_func (L, METHOD_FIND);
}


static int algf_match (lua_State *L) {
  return generic_find_func (L, METHOD_MATCH);
}


static int gmatch_iter (lua_State *L) {
  int last_end, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  last_end         = lua_tointeger (L, lua_upvalueindex (5));

  while (1) {
    if (argE.startoffset > (int)argE.textlen)
      return 0;
    res = gmatch_exec (ud, &argE);
    if (ALG_ISMATCH (res)) {
      int incr = 0;
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          argE.startoffset += ALG_CHARSIZE;
          continue;
        }
        incr = ALG_CHARSIZE;
      }
      last_end = ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0);
      lua_pushinteger(L, last_end + incr); /* update start offset */
      lua_replace (L, lua_upvalueindex (4));
      lua_pushinteger(L, last_end); /* update last end of match */
      lua_replace (L, lua_upvalueindex (5));
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text, NULL);
        return ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text, 0);
        return 1;
      }
    }
    else if (ALG_NOMATCH (res))
      return 0;
    else
      return generate_error (L, ud, res);
  }
}


static int split_iter (lua_State *L) {
  int incr, last_end, newoffset, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  incr             = lua_tointeger (L, lua_upvalueindex (5));
  last_end         = lua_tointeger (L, lua_upvalueindex (6));

  if (incr < 0)
    return 0;

  while (1) {
    if ((newoffset = argE.startoffset + incr) > (int)argE.textlen)
      break;
    res = split_exec (ud, &argE, newoffset);
    if (ALG_ISMATCH (res)) {
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          incr += ALG_CHARSIZE;
          continue;
        }
      }
      lua_pushinteger(L, ALG_BASE(newoffset) + ALG_SUBEND(ud,0)); /* update start offset and last_end */
      lua_pushvalue (L, -1);
      lua_replace (L, lua_upvalueindex (4));
      lua_replace (L, lua_upvalueindex (6));
      lua_pushinteger (L, ALG_SUBLEN(ud,0) ? 0 : ALG_CHARSIZE);    /* update incr */
      lua_replace (L, lua_upvalueindex (5));
      /* push text preceding the match */
      lua_pushlstring (L, argE.text + argE.startoffset,
                       ALG_SUBBEG(ud,0) + ALG_BASE(newoffset) - argE.startoffset);
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text + ALG_BASE(newoffset), NULL);
        return 1 + ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text + ALG_BASE(newoffset), 0);
        return 2;
      }
    }
    else if (ALG_NOMATCH (res))
      break;
    else
      return generate_error (L, ud, res);
  }
  lua_pushinteger (L, -1);    /* mark as last iteration */
  lua_replace (L, lua_upvalueindex (5));   /* incr = -1 */
  lua_pushlstring (L, argE.text+argE.startoffset, argE.textlen-argE.startoffset);
  return 1;
}


static int algf_gmatch (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, -1);                    /* 5-th upvalue: last end of match */
  lua_pushcclosure (L, gmatch_iter, 5);
  return 1;
}

static int algf_split (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, 0);                     /* 5-th upvalue: incr */
  lua_pushinteger (L, -1);                    /* 6-th upvalue: last_end */
  lua_pushcclosure (L, split_iter, 6);
  return 1;
}


static void push_substring_table (lua_State *L, TUserdata *ud, const char *text) {
  int i;
  lua_newtable (L);
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
    lua_rawseti (L, -2, i);
  }
}


static void push_offset_table (lua_State *L, TUserdata *ud, int startoffset) {
  int i, j;
  lua_newtable (L);
  for (i=1, j=1; i <= ALG_NSUB(ud); i++) {
    if (ALG_SUBVALID (ud,i)) {
      ALG_PUSHSTART (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
      ALG_PUSHEND (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
    }
    else {
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
    }
  }
}


static int generic_find_method (lua_State *L, int method) {
  TUserdata *ud;
  TArgExec argE;
  int res;

  checkarg_find_method (L, &argE, &ud);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil(L), 1;

  res = findmatch_exec (ud, &argE);
  if (ALG_ISMATCH (res)) {
    switch (method) {
      case METHOD_EXEC:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_offset_table (L, ud, ALG_BASE(argE.startoffset));
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_TFIND:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_substring_table (L, ud, argE.text);
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_MATCH:
      case METHOD_FIND:
        return finish_generic_find (L, ud, &argE, method, res);
    }
    return 0;
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error(L, ud, res);
}


static int algm_find (lua_State *L) {
  return generic_find_method (L, METHOD_FIND);
}
static int algm_match (lua_State *L) {
  return generic_find_method (L, METHOD_MATCH);
}
static int algm_tfind (lua_State *L) {
  return generic_find_method (L, METHOD_TFIND);
}
static int algm_exec (lua_State *L) {
  return generic_find_method (L, METHOD_EXEC);
}

static void alg_register (lua_State *L, const luaL_Reg *r_methods,
                          const luaL_Reg *r_functions, const char *name) {
  /* Create a new function environment to serve as a metatable for methods. */
  luaL_newmetatable(L, REX_TYPENAME);
  lua_pushvalue(L, -1);
  luaL_setfuncs (L, r_methods, 1);
  lua_pushvalue(L, -1); /* mt.__index = mt */
  lua_setfield(L, -2, "__index");

  /* Register functions. */
  lua_createtable(L, 0, 8);
  lua_pushvalue(L, -2);
  luaL_setfuncs (L, r_functions, 1);
#ifdef REX_CREATEGLOBALVAR
  lua_pushvalue(L, -1);
  lua_setglobal(L, REX_LIBNAME);
#endif
  lua_pushfstring (L, REX_VERSION" (for %s)", name);
  lua_setfield (L, -2, "_VERSION");
#ifndef REX_NOEMBEDDEDTEST
  lua_pushcfunction (L, newmembuffer);
  lua_setfield (L, -2, "_newmembuffer");
#endif
}
