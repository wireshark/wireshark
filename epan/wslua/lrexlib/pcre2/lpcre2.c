/* lpcre2.c - Lua binding of PCRE2 library */
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

#include <wireshark.h>
DIAG_OFF_CLANG(shorten-64-to-32)
DIAG_OFF_CLANG(comma)
#ifdef _MSC_VER
/* disable: " warning C4244: '=': conversion from 'lua _Integer' to 'int',
 * possible loss of data" */
#pragma warning(disable:4244)
/* warning C4267: '+=': conversion from 'size_t' to 'int',
 * possible loss of data */
#pragma warning(disable:4267)
#endif

#define malloc_free free
#define rex_atoi atoi

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <ctype.h>
#include <stdint.h>
#include <pcre2.h>

#include "lua.h"
#include "lauxlib.h"
#include "../common.h"

#include <wslua/wslua.h>

extern int Lpcre2_get_flags (lua_State *L);
extern int Lpcre2_config (lua_State *L);
extern flag_pair pcre2_error_flags[];

/* These 2 settings may be redefined from the command-line or the makefile.
 * They should be kept in sync between themselves and with the target name.
 */
#ifndef REX_LIBNAME
#  define REX_LIBNAME "rex_pcre2"
#endif
#ifndef REX_OPENLIB
#  define REX_OPENLIB luaopen_rex_pcre2
#endif

#define REX_TYPENAME REX_LIBNAME"_regex"

#define ALG_CFLAGS_DFLT 0
#define ALG_EFLAGS_DFLT 0

static int getcflags (lua_State *L, int pos);
#define ALG_GETCFLAGS(L,pos)  getcflags(L, pos)

static void checkarg_compile (lua_State *L, int pos, TArgComp *argC);
#define ALG_GETCARGS(a,b,c)  checkarg_compile(a,b,c)

#define ALG_NOMATCH(res)   ((res) == PCRE2_ERROR_NOMATCH)
#define ALG_ISMATCH(res)   ((res) >= 0)
#define ALG_SUBBEG(ud,n)   ((int)(ud)->ovector[(n)+(n)])
#define ALG_SUBEND(ud,n)   ((int)(ud)->ovector[(n)+(n)+1])
#define ALG_SUBLEN(ud,n)   (ALG_SUBEND((ud),(n)) - ALG_SUBBEG((ud),(n)))
#define ALG_SUBVALID(ud,n) (0 == pcre2_substring_length_bynumber((ud)->match_data, (n), NULL))
#define ALG_NSUB(ud)       ((int)(ud)->ncapt)

#define ALG_PUSHSUB(L,ud,text,n) \
  lua_pushlstring (L, (text) + ALG_SUBBEG((ud),(n)), ALG_SUBLEN((ud),(n)))

#define ALG_PUSHSUB_OR_FALSE(L,ud,text,n) \
  (ALG_SUBVALID(ud,n) ? (void) ALG_PUSHSUB (L,ud,text,n) : lua_pushboolean (L,0))

#define ALG_PUSHSTART(L,ud,offs,n)   lua_pushinteger(L, (offs) + ALG_SUBBEG(ud,n) + 1)
#define ALG_PUSHEND(L,ud,offs,n)     lua_pushinteger(L, (offs) + ALG_SUBEND(ud,n))
#define ALG_PUSHOFFSETS(L,ud,offs,n) \
  (ALG_PUSHSTART(L,ud,offs,n), ALG_PUSHEND(L,ud,offs,n))

#define ALG_BASE(st)  0
#define ALG_PULL

typedef struct {
  pcre2_code *pr;
  pcre2_compile_context *ccontext;
  pcre2_match_data *match_data;
  PCRE2_SIZE *ovector;
  int ncapt;
  const unsigned char *tables;
  int freed;
} TPcre2;

#define TUserdata TPcre2

static void do_named_subpatterns (lua_State *L, TPcre2 *ud, const char *text);
#  define DO_NAMED_SUBPATTERNS do_named_subpatterns

#include "../algo.h"

/* Locations of the 2 permanent tables in the function environment */
#define INDEX_CHARTABLES_META  1      /* chartables type's metatable */
#define INDEX_CHARTABLES_LINK  2      /* link chartables to compiled regex */

const char chartables_typename[] = "chartables";

/*  Functions
 ******************************************************************************
 */

static int push_error_message (lua_State *L, int errorcode) //### is this function needed?
{
  PCRE2_UCHAR buf[256];
  if (pcre2_get_error_message(errorcode, buf, 256) > 0)
  {
    lua_pushstring(L, (const char*)buf);
    return 1;
  }
  return 0;
}

static int getcflags (lua_State *L, int pos) {
  switch (lua_type (L, pos)) {
    case LUA_TNONE:
    case LUA_TNIL:
      return ALG_CFLAGS_DFLT;
    case LUA_TNUMBER:
      return lua_tointeger (L, pos);
    case LUA_TSTRING: {
      const char *s = lua_tostring (L, pos);
      int res = 0, ch;
      while ((ch = *s++) != '\0') {
        if (ch == 'i') res |= PCRE2_CASELESS;
        else if (ch == 'm') res |= PCRE2_MULTILINE;
        else if (ch == 's') res |= PCRE2_DOTALL;
        else if (ch == 'x') res |= PCRE2_EXTENDED;
        else if (ch == 'U') res |= PCRE2_UNGREEDY;
        //else if (ch == 'X') res |= PCRE2_EXTRA; //### does not exist in PCRE2 -> reflect in manual
      }
      return res;
    }
    default:
      return luaL_typerror (L, pos, "number or string");
  }
}

static int generate_error (lua_State *L, const TPcre2 *ud, int errcode) {
  const char *key = get_flag_key (pcre2_error_flags, errcode);
  (void) ud;
  if (key)
    return luaL_error (L, "error PCRE2_%s", key);
  else
    return luaL_error (L, "PCRE2 error code %d", errcode);
}

/* method r:dfa_exec (s, [st], [ef], [ovecsize], [wscount]) */
static void checkarg_dfa_exec (lua_State *L, TArgExec *argE, TPcre2 **ud) {
  *ud = check_ud (L);
  argE->text = luaL_checklstring (L, 2, &argE->textlen);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  argE->ovecsize = (size_t)luaL_optinteger (L, 5, 100);
  argE->wscount = (size_t)luaL_optinteger (L, 6, 50);
}

static void push_chartables_meta (lua_State *L) {
  lua_pushinteger (L, INDEX_CHARTABLES_META);
  lua_rawget (L, ALG_ENVIRONINDEX);
}

static int Lpcre2_maketables (lua_State *L) {
  *(const void**)lua_newuserdata (L, sizeof(void*)) = pcre2_maketables(NULL); //### argument NULL
  push_chartables_meta (L);
  lua_setmetatable (L, -2);
  return 1;
}

static void **check_chartables (lua_State *L, int pos) {
  void **q;
  /* Compare the metatable against the C function environment. */
  if (lua_getmetatable(L, pos)) {
    push_chartables_meta (L);
    if (lua_rawequal(L, -1, -2) &&
        (q = (void **)lua_touserdata(L, pos)) != NULL) {
      lua_pop(L, 2);
      return q;
    }
  }
  luaL_argerror(L, pos, lua_pushfstring (L, "not a %s", chartables_typename));
  return NULL;
}

static int chartables_gc (lua_State *L) {
  void **ud = check_chartables (L, 1);
  if (*ud) {
    malloc_free (*ud); //### free() should be called only if pcre2_maketables was called with NULL argument
    *ud = NULL;
  }
  return 0;
}

static int chartables_tostring (lua_State *L) {
  void **ud = check_chartables (L, 1);
  lua_pushfstring (L, "%s (%p)", chartables_typename, ud);
  return 1;
}

static void checkarg_compile (lua_State *L, int pos, TArgComp *argC) {
  argC->locale = NULL;
  argC->tables = NULL;
  if (!lua_isnoneornil (L, pos)) {
    if (lua_isstring (L, pos))
      argC->locale = lua_tostring (L, pos);
    else {
      argC->tablespos = pos;
      argC->tables = (const unsigned char*) *check_chartables (L, pos);
    }
  }
}

static int compile_regex (lua_State *L, const TArgComp *argC, TPcre2 **pud) {
  int errcode;
  PCRE2_SIZE erroffset;
  TPcre2 *ud;

  ud = (TPcre2*)lua_newuserdata (L, sizeof (TPcre2));
  memset (ud, 0, sizeof (TPcre2));           /* initialize all members to 0 */
  lua_pushvalue (L, ALG_ENVIRONINDEX);
  lua_setmetatable (L, -2);

  ud->ccontext = pcre2_compile_context_create(NULL);
  if (ud->ccontext == NULL)
    return luaL_error (L, "malloc failed");

  if (argC->locale) {
    char old_locale[256];
    g_strlcpy (old_locale, setlocale (LC_CTYPE, NULL), sizeof(old_locale));  /* store the locale */
    if (NULL == setlocale (LC_CTYPE, argC->locale))   /* set new locale */
      return luaL_error (L, "cannot set locale");
    ud->tables = pcre2_maketables (NULL); /* make tables with new locale */ //### argument NULL
    pcre2_set_character_tables(ud->ccontext, ud->tables);
    setlocale (LC_CTYPE, old_locale);          /* restore the old locale */
  }
  else if (argC->tables) {
    pcre2_set_character_tables(ud->ccontext, argC->tables);
    lua_pushinteger (L, INDEX_CHARTABLES_LINK);
    lua_rawget (L, ALG_ENVIRONINDEX);
    lua_pushvalue (L, -2);
    lua_pushvalue (L, argC->tablespos);
    lua_rawset (L, -3);
    lua_pop (L, 1);
  }

  ud->pr = pcre2_compile ((PCRE2_SPTR)argC->pattern, argC->patlen, argC->cflags, &errcode,
                          &erroffset, ud->ccontext); //### DOUBLE-CHECK ALL ARGUMENTS
  if (!ud->pr) {
    if (push_error_message(L, errcode))
      return luaL_error (L, "%s (pattern offset: %d)", lua_tostring(L,-1), erroffset + 1);
    else
      return luaL_error (L, "%s (pattern offset: %d)", "pattern compile error", erroffset + 1);
  }

  if (0 != pcre2_pattern_info (ud->pr, PCRE2_INFO_CAPTURECOUNT, &ud->ncapt)) //###
    return luaL_error (L, "could not get pattern info");

  /* need (2 ints per capture, plus one for substring match) * 3/2 */
  ud->match_data = pcre2_match_data_create(ud->ncapt+1, NULL); //### CHECK ALL
  if (!ud->match_data)
    return luaL_error (L, "malloc failed");

  ud->ovector = pcre2_get_ovector_pointer(ud->match_data);

  if (pud) *pud = ud;
  return 1;
}

/* the target table must be on lua stack top */
static void do_named_subpatterns (lua_State *L, TPcre2 *ud, const char *text) {
  int i, namecount, name_entry_size;
  unsigned char *name_table;
  PCRE2_SPTR tabptr;

  /* do named subpatterns - NJG */
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMECOUNT, &namecount);
  if (namecount <= 0)
    return;
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMETABLE, &name_table);
  pcre2_pattern_info (ud->pr, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);
  tabptr = name_table;
  for (i = 0; i < namecount; i++) {
    int n = (tabptr[0] << 8) | tabptr[1]; /* number of the capturing parenthesis */
    if (n > 0 && n <= ALG_NSUB(ud)) {   /* check range */
      lua_pushstring (L, (char *)tabptr + 2); /* name of the capture, zero terminated */
      ALG_PUSHSUB_OR_FALSE (L, ud, text, n);
      lua_rawset (L, -3);
    }
    tabptr += name_entry_size;
  }
}

static int Lpcre2_dfa_exec (lua_State *L)
{
  TArgExec argE;
  TPcre2 *ud;
  int res;
  int *wspace;
  size_t wsize;

  checkarg_dfa_exec (L, &argE, &ud);
  wsize = argE.wscount * sizeof(int);
  wspace = (int*) Lmalloc (L, wsize);
  if (!wspace)
    luaL_error (L, "malloc failed");

  ud->match_data = pcre2_match_data_create(argE.ovecsize/2, NULL); //### CHECK ALL
  if (!ud->match_data)
    return luaL_error (L, "malloc failed");

  res = pcre2_dfa_match (ud->pr, (PCRE2_SPTR)argE.text, argE.textlen, argE.startoffset,
    argE.eflags, ud->match_data, NULL, wspace, argE.wscount); //### CHECK ALL

  if (ALG_ISMATCH (res) || res == PCRE2_ERROR_PARTIAL) {
    int i;
    int max = (res>0) ? res : (res==0) ? (int)argE.ovecsize/2 : 1;
    PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(ud->match_data);

    lua_pushinteger (L, ovector[0] + 1);         /* 1-st return value */
    lua_newtable (L);                            /* 2-nd return value */
    for (i=0; i<max; i++) {
      lua_pushinteger (L, ovector[i+i+1]);
      lua_rawseti (L, -2, i+1);
    }
    lua_pushinteger (L, res);                    /* 3-rd return value */
    Lfree (L, wspace, wsize);
    return 3;
  }
  else {
    Lfree (L, wspace, wsize);
    if (ALG_NOMATCH (res))
      return lua_pushnil (L), 1;
    else
      return generate_error (L, ud, res);
  }
}

static int gmatch_exec (TUserdata *ud, TArgExec *argE) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    argE->startoffset, argE->eflags, ud->match_data, NULL); //###
}

static void gmatch_pushsubject (lua_State *L, TArgExec *argE) {
  lua_pushlstring (L, argE->text, argE->textlen);
}

static int findmatch_exec (TPcre2 *ud, TArgExec *argE) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    argE->startoffset, argE->eflags, ud->match_data, NULL); //###
}

static int gsub_exec (TPcre2 *ud, TArgExec *argE, int st) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    st, argE->eflags, ud->match_data, NULL); //###
}

static int split_exec (TPcre2 *ud, TArgExec *argE, int offset) {
  return pcre2_match (ud->pr, (PCRE2_SPTR)argE->text, argE->textlen,
    offset, argE->eflags, ud->match_data, NULL); //###
}

static int Lpcre2_gc (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  if (ud->freed == 0) {           /* precaution against "manual" __gc calling */
    ud->freed = 1;
    if (ud->pr) pcre2_code_free (ud->pr);
    //if (ud->tables)  pcre_free ((void *)ud->tables); //###
    if (ud->ccontext) pcre2_compile_context_free (ud->ccontext);
    if (ud->match_data) pcre2_match_data_free (ud->match_data);
  }
  return 0;
}

static int Lpcre2_tostring (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  if (ud->freed == 0)
    lua_pushfstring (L, "%s (%p)", REX_TYPENAME, (void*)ud);
  else
    lua_pushfstring (L, "%s (deleted)", REX_TYPENAME);
  return 1;
}

static int Lpcre2_version (lua_State *L) {
  char buf[64];
  pcre2_config(PCRE2_CONFIG_VERSION, buf);
  lua_pushstring (L, buf);
  return 1;
}

//### TODO: document this method.
//### TODO: write tests for this method.
static int Lpcre2_jit_compile (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  uint32_t options = (uint32_t) luaL_optinteger (L, 2, PCRE2_JIT_COMPLETE);
  int errcode = pcre2_jit_compile (ud->pr, options);
  if (errcode == 0) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  return 1 + push_error_message(L, errcode);
}

#define SET_INFO_FIELD(L,ud,what,name,valtype) { \
  valtype val; \
  if (0 == pcre2_pattern_info (ud->pr, what, &val)) { \
    lua_pushnumber (L, val); \
    lua_setfield (L, -2, name); \
  } \
}

static int Lpcre2_pattern_info (lua_State *L) {
  TPcre2 *ud = check_ud (L);
  lua_newtable(L);

  SET_INFO_FIELD (L, ud, PCRE2_INFO_ALLOPTIONS,          "ALLOPTIONS",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_ARGOPTIONS,          "ARGOPTIONS",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_BACKREFMAX,          "BACKREFMAX",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_BSR,                 "BSR",                 uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_CAPTURECOUNT,        "CAPTURECOUNT",        uint32_t)
  //### SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTBITMAP,   "FIRSTBITMAP",         ???)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTCODETYPE,       "FIRSTCODETYPE",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_FIRSTCODEUNIT,       "FIRSTCODEUNIT",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_HASBACKSLASHC,       "HASBACKSLASHC",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_HASCRORLF,           "HASCRORLF",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_JCHANGED,            "JCHANGED",            uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_JITSIZE,             "JITSIZE",             size_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_LASTCODETYPE,        "LASTCODETYPE",        uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_LASTCODEUNIT,        "LASTCODEUNIT",        uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MATCHEMPTY,          "MATCHEMPTY",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MATCHLIMIT,          "MATCHLIMIT",          uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MAXLOOKBEHIND,       "MAXLOOKBEHIND",       uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_MINLENGTH,           "MINLENGTH",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMECOUNT,           "NAMECOUNT",           uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMEENTRYSIZE,       "NAMEENTRYSIZE",       uint32_t)
  //### SET_INFO_FIELD (L, ud, PCRE2_INFO_NAMETABLE,     "NAMETABLE",           ???)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_NEWLINE,             "NEWLINE",             uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_RECURSIONLIMIT,      "RECURSIONLIMIT",      uint32_t)
  SET_INFO_FIELD (L, ud, PCRE2_INFO_SIZE,                "SIZE",                size_t)

  return 1;
}

static const luaL_Reg chartables_meta[] = {
  { "__gc",        chartables_gc },
  { "__tostring",  chartables_tostring },
  { NULL, NULL }
};

static const luaL_Reg r_methods[] = {
  { "exec",        algm_exec },
  { "tfind",       algm_tfind },    /* old name: match */
  { "find",        algm_find },
  { "match",       algm_match },
  { "dfa_exec",    Lpcre2_dfa_exec },
  { "patterninfo", Lpcre2_pattern_info }, //### document name change: fullinfo -> patterninfo
  { "fullinfo",    Lpcre2_pattern_info }, //### compatibility name
  { "jit_compile", Lpcre2_jit_compile },
  { "__gc",        Lpcre2_gc },
  { "__tostring",  Lpcre2_tostring },
  { NULL, NULL }
};

static const luaL_Reg r_functions[] = {
  { "match",       algf_match },
  { "find",        algf_find },
  { "gmatch",      algf_gmatch },
  { "gsub",        algf_gsub },
  { "count",       algf_count },
  { "split",       algf_split },
  { "new",         algf_new },
  { "flags",       Lpcre2_get_flags },
  { "version",     Lpcre2_version },
  { "maketables",  Lpcre2_maketables },
  { "config",      Lpcre2_config },
  { NULL, NULL }
};

/* Open the library */
REX_API int REX_OPENLIB (lua_State *L) {
  char buf_ver[64];
  pcre2_config(PCRE2_CONFIG_VERSION, buf_ver);
  if (PCRE2_MAJOR > rex_atoi (buf_ver)) {
    return luaL_error (L, "%s requires at least version %d of PCRE2 library",
      REX_LIBNAME, (int)PCRE2_MAJOR);
  }

  alg_register(L, r_methods, r_functions, "PCRE2");

  /* create a table and register it as a metatable for "chartables" userdata */
  lua_newtable (L);
  lua_pushliteral (L, "access denied");
  lua_setfield (L, -2, "__metatable");
#if LUA_VERSION_NUM == 501
  luaL_register (L, NULL, chartables_meta);
  lua_rawseti (L, LUA_ENVIRONINDEX, INDEX_CHARTABLES_META);
#else
  lua_pushvalue(L, -3);
  luaL_setfuncs (L, chartables_meta, 1);
  lua_rawseti (L, -3, INDEX_CHARTABLES_META);
#endif

  /* create a table for connecting "chartables" userdata to "regex" userdata */
  lua_newtable (L);
  lua_pushliteral (L, "k");         /* weak keys */
  lua_setfield (L, -2, "__mode");
  lua_pushvalue (L, -1);            /* setmetatable (tb, tb) */
  lua_setmetatable (L, -2);
#if LUA_VERSION_NUM == 501
  lua_rawseti (L, LUA_ENVIRONINDEX, INDEX_CHARTABLES_LINK);
#else
  lua_rawseti (L, -3, INDEX_CHARTABLES_LINK);
#endif

  return 1;
}
