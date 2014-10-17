/* common.c */
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

/*
 * Modified to use the g_ascii_isXXX() routines instead of
 * the ctype.h isXXX() routines, to avoid locale dependency
 * and to handle possibly-signed chars.
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "lua.h"
#include "lauxlib.h"
#include "lrexlib.h"

#define N_ALIGN sizeof(int)

/* the table must be on Lua stack top */
int get_int_field (lua_State *L, const char* field)
{
  int val;
  lua_getfield (L, -1, field);
  val = (int) lua_tointeger (L, -1);
  lua_pop (L, 1);
  return val;
}

/* the table must be on Lua stack top */
void set_int_field (lua_State *L, const char* field, int val)
{
  lua_pushinteger (L, val);
  lua_setfield (L, -2, field);
}

void *Lmalloc(lua_State *L, size_t size) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  return lalloc(ud, NULL, 0, size);
}

void *Lrealloc(lua_State *L, void *p, size_t osize, size_t nsize) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  return lalloc(ud, p, osize, nsize);
}

void Lfree(lua_State *L, void *p, size_t osize) {
  void *ud;
  lua_Alloc lalloc = lua_getallocf(L, &ud);
  lalloc(ud, p, osize, 0);
}

/* This function fills a table with string-number pairs.
   The table can be passed as the 1-st lua-function parameter,
   otherwise it is created. The return value is the filled table.
*/
int get_flags (lua_State *L, const flag_pair **arrs) {
  const flag_pair *p;
  const flag_pair **pp;
  int nparams = lua_gettop(L);

  if(nparams == 0)
    lua_newtable(L);
  else {
    if(!lua_istable(L, 1))
      luaL_argerror(L, 1, "not a table");
    if(nparams > 1)
      lua_pushvalue(L, 1);
  }

  for(pp=arrs; *pp; ++pp) {
    for(p=*pp; p->key; ++p) {
      lua_pushstring(L, p->key);
      lua_pushinteger(L, p->val);
      lua_rawset(L, -3);
    }
  }
  return 1;
}

const char *get_flag_key (const flag_pair *fp, int val) {
  for (; fp->key; ++fp) {
    if (fp->val == val)
      return fp->key;
  }
  return NULL;
}

/* Classes */

/*
 *  class TFreeList
 *  ***************
 *  Simple array of pointers to TBuffer's.
 *  The array has fixed capacity (not expanded automatically).
 */

void freelist_init (TFreeList *fl) {
  fl->top = 0;
}

void freelist_add (TFreeList *fl, TBuffer *buf) {
  fl->list[fl->top++] = buf;
}

void freelist_free (TFreeList *fl) {
  while (fl->top > 0)
    buffer_free (fl->list[--fl->top]);
}

/*
 *  class TBuffer
 *  *************
 *  Auto-extensible array of characters for building long strings incrementally.
 *    * Differs from luaL_Buffer in that:
 *       *  its operations do not change Lua stack top position
 *       *  buffer_addvalue does not extract the value from Lua stack
 *       *  buffer_pushresult does not have to be the last operation
 *    * Uses TFreeList class:
 *       *  for inserting itself into a TFreeList instance for future clean-up
 *       *  calls freelist_free prior to calling luaL_error.
 *    * Has specialized "Z-operations" for maintaining mixed string/integer
 *      array:  bufferZ_addlstring, bufferZ_addnum and bufferZ_next.
 *       *  if the array is intended to be "mixed", then the methods
 *          buffer_addlstring and buffer_addvalue must not be used
 *          (the application will crash on bufferZ_next).
 *       *  conversely, if the array is not intended to be "mixed",
 *          then the method bufferZ_next must not be used.
 */

enum { ID_NUMBER, ID_STRING };

void buffer_init (TBuffer *buf, size_t sz, lua_State *L, TFreeList *fl) {
  buf->arr = (char *)Lmalloc(L, sz);
  if (!buf->arr) {
    freelist_free (fl);
    luaL_error (L, "malloc failed");
    return;
  }
  buf->size = sz;
  buf->top = 0;
  buf->L = L;
  buf->freelist = fl;
  freelist_add (fl, buf);
}

void buffer_free (TBuffer *buf) {
  Lfree(buf->L, buf->arr, buf->size);
}

void buffer_clear (TBuffer *buf) {
  buf->top = 0;
}

void buffer_pushresult (TBuffer *buf) {
  lua_pushlstring (buf->L, buf->arr, buf->top);
}

void buffer_addbuffer (TBuffer *trg, TBuffer *src) {
  buffer_addlstring (trg, src->arr, src->top);
}

void buffer_addlstring (TBuffer *buf, const void *src, size_t sz) {
  size_t newtop = buf->top + sz;
  if (newtop > buf->size) {
    char *p = (char*) Lrealloc (buf->L, buf->arr, buf->size, 2 * newtop);   /* 2x expansion */
    if (!p) {
      freelist_free (buf->freelist);
      luaL_error (buf->L, "realloc failed");
      return;
    }
    buf->arr = p;
    buf->size = 2 * newtop;
  }
  if (src)
    memcpy (buf->arr + buf->top, src, sz);
  buf->top = newtop;
}

void buffer_addvalue (TBuffer *buf, int stackpos) {
  size_t len;
  const char *p = lua_tolstring (buf->L, stackpos, &len);
  buffer_addlstring (buf, p, len);
}

void bufferZ_addlstring (TBuffer *buf, const void *src, size_t len) {
  int n;
  size_t header[2] = { ID_STRING };
  header[1] = len;
  buffer_addlstring (buf, header, sizeof (header));
  buffer_addlstring (buf, src, len);
  n = (int)(len % N_ALIGN);
  if (n) buffer_addlstring (buf, NULL, N_ALIGN - n);
}

void bufferZ_addnum (TBuffer *buf, size_t num) {
  size_t header[2] = { ID_NUMBER };
  header[1] = num;
  buffer_addlstring (buf, header, sizeof (header));
}

/* 1. When called repeatedly on the same TBuffer, its existing data
      is discarded and overwritten by the new data.
   2. The TBuffer's array is never shrunk by this function.
*/
void bufferZ_putrepstring (TBuffer *BufRep, int reppos, int nsub) {
  char dbuf[] = { 0, 0 };
  size_t replen;
  const char *p = lua_tolstring (BufRep->L, reppos, &replen);
  const char *end = p + replen;
  BufRep->top = 0;
  while (p < end) {
    const char *q;
    for (q = p; q < end && *q != '%'; ++q)
      {}
    if (q != p)
      bufferZ_addlstring (BufRep, p, q - p);
    if (q < end) {
      if (++q < end) {  /* skip % */
        if (g_ascii_isdigit (*q)) {
          int num;
          *dbuf = *q;
          num = (int) strtol (dbuf, NULL, 10);
          if (num == 1 && nsub == 0)
            num = 0;
          else if (num > nsub) {
            freelist_free (BufRep->freelist);
            luaL_error (BufRep->L, "invalid capture index");
            return;
          }
          bufferZ_addnum (BufRep, num);
        }
        else bufferZ_addlstring (BufRep, q, 1);
      }
      p = q + 1;
    }
    else break;
  }
}

/******************************************************************************
  The intended use of this function is as follows:
        size_t iter = 0;
        while (bufferZ_next (buf, &iter, &num, &str)) {
          if (str) do_something_with_string (str, num);
          else     do_something_with_number (num);
        }
*******************************************************************************
*/
int bufferZ_next (TBuffer *buf, size_t *iter, size_t *num, const char **str) {
  if (*iter < buf->top) {
    size_t *ptr_header = (size_t*)(void*)(buf->arr + *iter);
    *num = ptr_header[1];
    *iter += 2 * sizeof (size_t);
    *str = NULL;
    if (*ptr_header == ID_STRING) {
      int n;
      *str = buf->arr + *iter;
      *iter += *num;
      n = (int)(*iter % N_ALIGN);
      if (n) *iter += (N_ALIGN - n);
    }
    return 1;
  }
  return 0;
}

#if LUA_VERSION_NUM > 501
int luaL_typerror (lua_State *L, int narg, const char *tname) {
  const char *msg = lua_pushfstring(L, "%s expected, got %s",
                                    tname, luaL_typename(L, narg));
  return luaL_argerror(L, narg, msg);
}
#endif
