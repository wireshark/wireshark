/* lpcre2_f.c - Lua binding of PCRE2 library */
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

#include <pcre2.h>
#include "lua.h"
#include "lauxlib.h"
#include "../common.h"

#define VERSION_PCRE2 (PCRE2_MAJOR*100 + PCRE2_MINOR)

extern int Lpcre2_get_flags (lua_State *L);
extern int Lpcre2_config (lua_State *L);

static flag_pair pcre2_flags[] = {
  { "MAJOR",                         PCRE2_MAJOR },
  { "MINOR",                         PCRE2_MINOR },
/*---------------------------------------------------------------------------*/
  { "ANCHORED",                      PCRE2_ANCHORED },
  { "NO_UTF_CHECK",                  PCRE2_NO_UTF_CHECK },
  { "ALLOW_EMPTY_CLASS",             PCRE2_ALLOW_EMPTY_CLASS },
  { "ALT_BSUX",                      PCRE2_ALT_BSUX },
  { "AUTO_CALLOUT",                  PCRE2_AUTO_CALLOUT },
  { "CASELESS",                      PCRE2_CASELESS },
  { "DOLLAR_ENDONLY",                PCRE2_DOLLAR_ENDONLY },
  { "DOTALL",                        PCRE2_DOTALL },
  { "DUPNAMES",                      PCRE2_DUPNAMES },
  { "EXTENDED",                      PCRE2_EXTENDED },
  { "FIRSTLINE",                     PCRE2_FIRSTLINE },
  { "MATCH_UNSET_BACKREF",           PCRE2_MATCH_UNSET_BACKREF },
  { "MULTILINE",                     PCRE2_MULTILINE },
  { "NEVER_UCP",                     PCRE2_NEVER_UCP },
  { "NEVER_UTF",                     PCRE2_NEVER_UTF },
  { "NO_AUTO_CAPTURE",               PCRE2_NO_AUTO_CAPTURE },
  { "NO_AUTO_POSSESS",               PCRE2_NO_AUTO_POSSESS },
  { "NO_DOTSTAR_ANCHOR",             PCRE2_NO_DOTSTAR_ANCHOR },
  { "NO_START_OPTIMIZE",             PCRE2_NO_START_OPTIMIZE },
  { "UCP",                           PCRE2_UCP },
  { "UNGREEDY",                      PCRE2_UNGREEDY },
  { "UTF",                           PCRE2_UTF },
  { "NEVER_BACKSLASH_C",             PCRE2_NEVER_BACKSLASH_C },
  { "ALT_CIRCUMFLEX",                PCRE2_ALT_CIRCUMFLEX },
  { "ALT_VERBNAMES",                 PCRE2_ALT_VERBNAMES },
  { "USE_OFFSET_LIMIT",              PCRE2_USE_OFFSET_LIMIT },
  { "JIT_COMPLETE",                  PCRE2_JIT_COMPLETE },
  { "JIT_PARTIAL_SOFT",              PCRE2_JIT_PARTIAL_SOFT },
  { "JIT_PARTIAL_HARD",              PCRE2_JIT_PARTIAL_HARD },
  { "NOTBOL",                        PCRE2_NOTBOL },
  { "NOTEOL",                        PCRE2_NOTEOL },
  { "NOTEMPTY",                      PCRE2_NOTEMPTY },
  { "NOTEMPTY_ATSTART",              PCRE2_NOTEMPTY_ATSTART },
  { "PARTIAL_SOFT",                  PCRE2_PARTIAL_SOFT },
  { "PARTIAL_HARD",                  PCRE2_PARTIAL_HARD },
  { "DFA_RESTART",                   PCRE2_DFA_RESTART },
  { "DFA_SHORTEST",                  PCRE2_DFA_SHORTEST },
  { "SUBSTITUTE_GLOBAL",             PCRE2_SUBSTITUTE_GLOBAL },
  { "SUBSTITUTE_EXTENDED",           PCRE2_SUBSTITUTE_EXTENDED },
  { "SUBSTITUTE_UNSET_EMPTY",        PCRE2_SUBSTITUTE_UNSET_EMPTY },
  { "SUBSTITUTE_UNKNOWN_UNSET",      PCRE2_SUBSTITUTE_UNKNOWN_UNSET },
  { "SUBSTITUTE_OVERFLOW_LENGTH",    PCRE2_SUBSTITUTE_OVERFLOW_LENGTH },
#ifdef PCRE2_NO_JIT
  { "NO_JIT",                        PCRE2_NO_JIT },
#endif
  { "NEWLINE_CR",                    PCRE2_NEWLINE_CR },
  { "NEWLINE_LF",                    PCRE2_NEWLINE_LF },
  { "NEWLINE_CRLF",                  PCRE2_NEWLINE_CRLF },
  { "NEWLINE_ANY",                   PCRE2_NEWLINE_ANY },
  { "NEWLINE_ANYCRLF",               PCRE2_NEWLINE_ANYCRLF },
  { "BSR_UNICODE",                   PCRE2_BSR_UNICODE },
  { "BSR_ANYCRLF",                   PCRE2_BSR_ANYCRLF },
/*---------------------------------------------------------------------------*/
  { "INFO_ALLOPTIONS",               PCRE2_INFO_ALLOPTIONS },
  { "INFO_ARGOPTIONS",               PCRE2_INFO_ARGOPTIONS },
  { "INFO_BACKREFMAX",               PCRE2_INFO_BACKREFMAX },
  { "INFO_BSR",                      PCRE2_INFO_BSR },
  { "INFO_CAPTURECOUNT",             PCRE2_INFO_CAPTURECOUNT },
  { "INFO_FIRSTCODEUNIT",            PCRE2_INFO_FIRSTCODEUNIT },
  { "INFO_FIRSTCODETYPE",            PCRE2_INFO_FIRSTCODETYPE },
  { "INFO_FIRSTBITMAP",              PCRE2_INFO_FIRSTBITMAP },
  { "INFO_HASCRORLF",                PCRE2_INFO_HASCRORLF },
  { "INFO_JCHANGED",                 PCRE2_INFO_JCHANGED },
  { "INFO_JITSIZE",                  PCRE2_INFO_JITSIZE },
  { "INFO_LASTCODEUNIT",             PCRE2_INFO_LASTCODEUNIT },
  { "INFO_LASTCODETYPE",             PCRE2_INFO_LASTCODETYPE },
  { "INFO_MATCHEMPTY",               PCRE2_INFO_MATCHEMPTY },
  { "INFO_MATCHLIMIT",               PCRE2_INFO_MATCHLIMIT },
  { "INFO_MAXLOOKBEHIND",            PCRE2_INFO_MAXLOOKBEHIND },
  { "INFO_MINLENGTH",                PCRE2_INFO_MINLENGTH },
  { "INFO_NAMECOUNT",                PCRE2_INFO_NAMECOUNT },
  { "INFO_NAMEENTRYSIZE",            PCRE2_INFO_NAMEENTRYSIZE },
  { "INFO_NAMETABLE",                PCRE2_INFO_NAMETABLE },
  { "INFO_NEWLINE",                  PCRE2_INFO_NEWLINE },
  { "INFO_RECURSIONLIMIT",           PCRE2_INFO_RECURSIONLIMIT },
  { "INFO_SIZE",                     PCRE2_INFO_SIZE },
  { "INFO_HASBACKSLASHC",            PCRE2_INFO_HASBACKSLASHC },
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

flag_pair pcre2_error_flags[] = {
  { "ERROR_NOMATCH",                 PCRE2_ERROR_NOMATCH },
  { "ERROR_PARTIAL",                 PCRE2_ERROR_PARTIAL },
  { "ERROR_UTF8_ERR1",               PCRE2_ERROR_UTF8_ERR1 },
  { "ERROR_UTF8_ERR2",               PCRE2_ERROR_UTF8_ERR2 },
  { "ERROR_UTF8_ERR3",               PCRE2_ERROR_UTF8_ERR3 },
  { "ERROR_UTF8_ERR4",               PCRE2_ERROR_UTF8_ERR4 },
  { "ERROR_UTF8_ERR5",               PCRE2_ERROR_UTF8_ERR5 },
  { "ERROR_UTF8_ERR6",               PCRE2_ERROR_UTF8_ERR6 },
  { "ERROR_UTF8_ERR7",               PCRE2_ERROR_UTF8_ERR7 },
  { "ERROR_UTF8_ERR8",               PCRE2_ERROR_UTF8_ERR8 },
  { "ERROR_UTF8_ERR9",               PCRE2_ERROR_UTF8_ERR9 },
  { "ERROR_UTF8_ERR10",              PCRE2_ERROR_UTF8_ERR10 },
  { "ERROR_UTF8_ERR11",              PCRE2_ERROR_UTF8_ERR11 },
  { "ERROR_UTF8_ERR12",              PCRE2_ERROR_UTF8_ERR12 },
  { "ERROR_UTF8_ERR13",              PCRE2_ERROR_UTF8_ERR13 },
  { "ERROR_UTF8_ERR14",              PCRE2_ERROR_UTF8_ERR14 },
  { "ERROR_UTF8_ERR15",              PCRE2_ERROR_UTF8_ERR15 },
  { "ERROR_UTF8_ERR16",              PCRE2_ERROR_UTF8_ERR16 },
  { "ERROR_UTF8_ERR17",              PCRE2_ERROR_UTF8_ERR17 },
  { "ERROR_UTF8_ERR18",              PCRE2_ERROR_UTF8_ERR18 },
  { "ERROR_UTF8_ERR19",              PCRE2_ERROR_UTF8_ERR19 },
  { "ERROR_UTF8_ERR20",              PCRE2_ERROR_UTF8_ERR20 },
  { "ERROR_UTF8_ERR21",              PCRE2_ERROR_UTF8_ERR21 },
  { "ERROR_UTF16_ERR1",              PCRE2_ERROR_UTF16_ERR1 },
  { "ERROR_UTF16_ERR2",              PCRE2_ERROR_UTF16_ERR2 },
  { "ERROR_UTF16_ERR3",              PCRE2_ERROR_UTF16_ERR3 },
  { "ERROR_UTF32_ERR1",              PCRE2_ERROR_UTF32_ERR1 },
  { "ERROR_UTF32_ERR2",              PCRE2_ERROR_UTF32_ERR2 },
  { "ERROR_BADDATA",                 PCRE2_ERROR_BADDATA },
  { "ERROR_MIXEDTABLES",             PCRE2_ERROR_MIXEDTABLES },
  { "ERROR_BADMAGIC",                PCRE2_ERROR_BADMAGIC },
  { "ERROR_BADMODE",                 PCRE2_ERROR_BADMODE },
  { "ERROR_BADOFFSET",               PCRE2_ERROR_BADOFFSET },
  { "ERROR_BADOPTION",               PCRE2_ERROR_BADOPTION },
  { "ERROR_BADREPLACEMENT",          PCRE2_ERROR_BADREPLACEMENT },
  { "ERROR_BADUTFOFFSET",            PCRE2_ERROR_BADUTFOFFSET },
  { "ERROR_CALLOUT",                 PCRE2_ERROR_CALLOUT },
  { "ERROR_DFA_BADRESTART",          PCRE2_ERROR_DFA_BADRESTART },
  { "ERROR_DFA_RECURSE",             PCRE2_ERROR_DFA_RECURSE },
  { "ERROR_DFA_UCOND",               PCRE2_ERROR_DFA_UCOND },
  { "ERROR_DFA_UFUNC",               PCRE2_ERROR_DFA_UFUNC },
  { "ERROR_DFA_UITEM",               PCRE2_ERROR_DFA_UITEM },
  { "ERROR_DFA_WSSIZE",              PCRE2_ERROR_DFA_WSSIZE },
  { "ERROR_INTERNAL",                PCRE2_ERROR_INTERNAL },
  { "ERROR_JIT_BADOPTION",           PCRE2_ERROR_JIT_BADOPTION },
  { "ERROR_JIT_STACKLIMIT",          PCRE2_ERROR_JIT_STACKLIMIT },
  { "ERROR_MATCHLIMIT",              PCRE2_ERROR_MATCHLIMIT },
  { "ERROR_NOMEMORY",                PCRE2_ERROR_NOMEMORY },
  { "ERROR_NOSUBSTRING",             PCRE2_ERROR_NOSUBSTRING },
  { "ERROR_NOUNIQUESUBSTRING",       PCRE2_ERROR_NOUNIQUESUBSTRING },
  { "ERROR_NULL",                    PCRE2_ERROR_NULL },
  { "ERROR_RECURSELOOP",             PCRE2_ERROR_RECURSELOOP },
  { "ERROR_RECURSIONLIMIT",          PCRE2_ERROR_RECURSIONLIMIT },
  { "ERROR_UNAVAILABLE",             PCRE2_ERROR_UNAVAILABLE },
  { "ERROR_UNSET",                   PCRE2_ERROR_UNSET },
  { "ERROR_BADOFFSETLIMIT",          PCRE2_ERROR_BADOFFSETLIMIT },
  { "ERROR_BADREPESCAPE",            PCRE2_ERROR_BADREPESCAPE },
  { "ERROR_REPMISSINGBRACE",         PCRE2_ERROR_REPMISSINGBRACE },
  { "ERROR_BADSUBSTITUTION",         PCRE2_ERROR_BADSUBSTITUTION },
  { "ERROR_BADSUBSPATTERN",          PCRE2_ERROR_BADSUBSPATTERN },
  { "ERROR_TOOMANYREPLACE",          PCRE2_ERROR_TOOMANYREPLACE },
#ifdef PCRE2_ERROR_BADSERIALIZEDDATA
  { "ERROR_BADSERIALIZEDDATA",       PCRE2_ERROR_BADSERIALIZEDDATA },
#endif
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

static flag_pair pcre2_config_flags[] = {
  { "PCRE2_CONFIG_BSR",              PCRE2_CONFIG_BSR },
  { "PCRE2_CONFIG_JIT",              PCRE2_CONFIG_JIT },
  { "PCRE2_CONFIG_JITTARGET",        PCRE2_CONFIG_JITTARGET },
  { "PCRE2_CONFIG_LINKSIZE",         PCRE2_CONFIG_LINKSIZE },
  { "PCRE2_CONFIG_MATCHLIMIT",       PCRE2_CONFIG_MATCHLIMIT },
  { "PCRE2_CONFIG_NEWLINE",          PCRE2_CONFIG_NEWLINE },
  { "PCRE2_CONFIG_PARENSLIMIT",      PCRE2_CONFIG_PARENSLIMIT },
  { "PCRE2_CONFIG_RECURSIONLIMIT",   PCRE2_CONFIG_RECURSIONLIMIT },
  { "PCRE2_CONFIG_STACKRECURSE",     PCRE2_CONFIG_STACKRECURSE },
  { "PCRE2_CONFIG_UNICODE",          PCRE2_CONFIG_UNICODE },
  { "PCRE2_CONFIG_UNICODE_VERSION",  PCRE2_CONFIG_UNICODE_VERSION },
  { "PCRE2_CONFIG_VERSION",          PCRE2_CONFIG_VERSION },
/*---------------------------------------------------------------------------*/
  { NULL, 0 }
};

extern int Lpcre2_config (lua_State *L) {
  flag_pair *fp;
  if (lua_istable (L, 1))
    lua_settop (L, 1);
  else
    lua_newtable (L);
  for (fp = pcre2_config_flags; fp->key; ++fp) {
    if (fp->val == PCRE2_CONFIG_JITTARGET) {
#if PCRE2_CODE_UNIT_WIDTH == 8
      char buf[64];
      if (PCRE2_ERROR_BADOPTION != pcre2_config (fp->val, buf)) {
        lua_pushstring (L, buf);
        lua_setfield (L, -2, fp->key);
      }
#endif
    }
    else {
      int val;
      if (0 == pcre2_config (fp->val, &val)) {
        lua_pushinteger (L, val);
        lua_setfield (L, -2, fp->key);
      }
    }
  }
  return 1;
}

extern int Lpcre2_get_flags (lua_State *L) {
  const flag_pair* fps[] = { pcre2_flags, pcre2_error_flags, NULL };
  return get_flags (L, fps);
}
