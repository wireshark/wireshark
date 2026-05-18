/* lpcre2_f.h - Lua binding of PCRE2 library */
/* See Copyright Notice in the file LICENSE */
/* SPDX-License-Identifier: MIT */

#include "../common.h"

extern int Lpcre2_get_flags (lua_State *L);
extern int Lpcre2_config (lua_State *L);
extern flag_pair pcre2_error_flags[];
