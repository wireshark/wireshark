/* common.h */
/*
License of Lrexlib release
--------------------------

Copyright (C) Reuben Thomas 2000-2012
Copyright (C) Shmuel Zeigerman 2004-2012

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef _LREXLIB_H
#define _LREXLIB_H

#include "lua.h"

#define VERSION "2.7.2"

#define LREXLIB_WIRESHARK

#if LUA_VERSION_NUM > 501
  int luaL_typerror (lua_State *L, int narg, const char *tname);
#endif

/* REX_API can be overridden from the command line or Makefile */
#ifndef REX_API
#  define REX_API LUALIB_API
#endif

#ifndef REX_OPENLIB
#  define REX_OPENLIB luaopen_rex_glib
#endif

/* public function declarations */
REX_API int REX_OPENLIB (lua_State *L);
int Gregex_get_compile_flags (lua_State *L);
int Gregex_get_match_flags (lua_State *L);
int Gregex_get_flags (lua_State *L);

/* Special values for maxmatch in gsub. They all must be negative. */
#define GSUB_UNLIMITED   -1
#define GSUB_CONDITIONAL -2

/* Common structs and functions */

typedef struct {
  const char* key;
  int val;
} flag_pair;

typedef struct {            /* compile arguments */
  const char * pattern;
  size_t       patlen;
  void       * ud;
  int          cflags;
  const char * locale;             /* PCRE, Oniguruma */
  const unsigned char * tables;    /* PCRE */
  int          tablespos;          /* PCRE */
  void       * syntax;             /* Oniguruma */
  const unsigned char * translate; /* GNU */
  int          gnusyn;             /* GNU */
} TArgComp;

typedef struct {            /* exec arguments */
  const char * text;
  size_t       textlen;
  int          startoffset;
  int          eflags;
  int          funcpos;
  int          maxmatch;
  int          funcpos2;          /* used with gsub */
  int          reptype;           /* used with gsub */
  size_t       ovecsize;          /* PCRE: dfa_exec */
  size_t       wscount;           /* PCRE: dfa_exec */
} TArgExec;

struct tagFreeList; /* forward declaration */

struct tagBuffer {
  size_t      size;
  size_t      top;
  char      * arr;
  lua_State * L;
  struct tagFreeList * freelist;
};

struct tagFreeList {
  struct tagBuffer * list[16];
  int top;
};

typedef struct tagBuffer TBuffer;
typedef struct tagFreeList TFreeList;

void freelist_init (TFreeList *fl);
void freelist_add (TFreeList *fl, TBuffer *buf);
void freelist_free (TFreeList *fl);

void buffer_init (TBuffer *buf, size_t sz, lua_State *L, TFreeList *fl);
void buffer_free (TBuffer *buf);
void buffer_clear (TBuffer *buf);
void buffer_addbuffer (TBuffer *trg, TBuffer *src);
void buffer_addlstring (TBuffer *buf, const void *src, size_t sz);
void buffer_addvalue (TBuffer *buf, int stackpos);
void buffer_pushresult (TBuffer *buf);

void bufferZ_putrepstring (TBuffer *buf, int reppos, int nsub);
int  bufferZ_next (TBuffer *buf, size_t *iter, size_t *len, const char **str);
void bufferZ_addlstring (TBuffer *buf, const void *src, size_t len);
void bufferZ_addnum (TBuffer *buf, size_t num);

int  get_int_field (lua_State *L, const char* field);
void set_int_field (lua_State *L, const char* field, int val);
int  get_flags (lua_State *L, const flag_pair **arr);
const char *get_flag_key (const flag_pair *fp, int val);
void *Lmalloc (lua_State *L, size_t size);
void *Lrealloc (lua_State *L, void *p, size_t osize, size_t nsize);
void Lfree (lua_State *L, void *p, size_t size);

#endif
