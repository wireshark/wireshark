/******************************************************************************
* Copyright (C) 2010-2012 Lua.org, PUC-Rio.  All rights reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/
/*
** {======================================================
** Library for packing/unpacking structures.
** See Copyright Notice above.
**
** Small changes were made by Hadriel Kaplan - those changes
** are in the Public Domain.
**
** Some changes are based on a patch to struct.h from
** Flemming Madsen, from here:
** http://lua-users.org/lists/lua-l/2009-10/msg00572.html
** In particular, these changes from him:
** -Can handle 'long long' integers (i8 / I8); though they're converted to doubles
** -Can insert/specify padding anywhere in a struct. ('X' eg. when a string is following a union)
** -Can report current offset in both pack and unpack ('=')
** -Can mask out return values when you only want to calculate sizes or unmarshal pascal-style strings. '(' & ')'
**
** Changes I made:
** -Added support for Int64/UInt64 being packed/unpacked, using 'e'/'E'
** -Made it follow Wireshark's conventions so we could get API docs
** =======================================================
*/
/*
** Valid formats:
** > - big endian
** < - little endian
** ![num] - alignment
** x[num]   - pad num bytes, default 1
** X[num]   - pad to num align, default MAXALIGN
**
** Following are system-dependent sizes:
** i/I - signed/unsigned int
** l/L - signed/unsigned long
** f   - float
** T   - size_t
**
** Following are system-independent sizes:
** b/B   - signed/unsigned byte
** h/H   - signed/unsigned short
** in/In - signed/unsigned integer of size `n' bytes
          Note: unpack of i/I is done to a Lua_number, typically a double,
          so unpacking a 64-bit field (i8/I8) will lose precision.
          Use e/E to unpack into a Wireshark Int64/UInt64 object/userdata instead.
** e/E   - signed/unsigned eight-byte Integer (64bits, long long), to/from Int64/UInt64 object
** d     - double
** cn    - sequence of `n' chars (from/to a string); when packing, n==0 means
           the whole string; when unpacking, n==0 means use the previous
           read number as the string length
** s  - zero-terminated string
** ' ' - ignored
** '(' ')'  - stop assigning items. ')' start assigning (padding when packing)
** '='      - return current position / offset
*/

#include "config.h"

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#include <stdio.h>

#include "wslua.h"

/* WSLUA_MODULE Struct Binary encode/decode support

  The Struct class offers basic facilities to convert Lua values to and from C-style structs
  in binary Lua strings.  This is based on Roberto Ierusalimschy's Lua struct library found
  in [[http://www.inf.puc-rio.br/~roberto/struct/]], with some minor modifications as follows:
    * Added support for `Int64`/`UInt64` being packed/unpacked, using 'e'/'E'.
    * Can handle 'long long' integers (i8 / I8); though they're converted to doubles.
    * Can insert/specify padding anywhere in a struct. ('X' eg. when a string is following a union).
    * Can report current offset in both `pack` and `unpack` ('`=`').
    * Can mask out return values when you only want to calculate sizes or unmarshal
      pascal-style strings using '`(`' & '`)`'.

  All but the first of those changes are based on an email from Flemming Madsen, on the lua-users
  mailing list, which can be found [[http://lua-users.org/lists/lua-l/2009-10/msg00572.html|here]].

  The main functions are `Struct.pack`, which packs multiple Lua values into a struct-like
  Lua binary string; and `Struct.unpack`, which unpacks multiple Lua values from a given
  struct-like Lua binary string. There are some additional helper functions available as well.

  All functions in the Struct library are called as static member functions, not object methods,
  so they are invoked as "Struct.pack(...)" instead of "object:pack(...)".

  The fist argument to several of the `Struct` functions is a format string, which describes
  the layout of the structure. The format string is a sequence of conversion elements, which
  respect the current endianness and the current alignment requirements. Initially, the
  current endianness is the machine's native endianness and the current alignment requirement
  is 1 (meaning no alignment at all). You can change these settings with appropriate directives
  in the format string.

  The supported elements in the format string are as follows:

    * `$$ $$' (empty space) ignored.
    * `++!++__n__' flag to set the current alignment requirement to 'n' (necessarily a power of 2);
      an absent 'n' means the machine's native alignment.
    * `++>++' flag to set mode to big endian (i.e., network-order).
    * `++<++' flag to set mode to little endian.
    * `++x++' a padding zero byte with no corresponding Lua value.
    * `++b++' a signed char.
    * `++B++' an unsigned char.
    * `++h++' a signed short (native size).
    * `++H++' an unsigned short (native size).
    * `++l++' a signed long (native size).
    * `++L++' an unsigned long (native size).
    * `++T++' a size_t (native size).
    * `++i++__n__' a signed integer with 'n' bytes. An absent 'n' means the native size of an int.
    * `++I++__n__' like `++i++__n__' but unsigned.
    * `++e++' signed 8-byte Integer (64-bits, long long), to/from a +Int64+ object.
    * `++E++' unsigned 8-byte Integer (64-bits, long long), to/from a +UInt64+ object.
    * `++f++' a float (native size).
    * `++d++' a double (native size).
    * `++s++' a zero-terminated string.
    * `++c++__n__' a sequence of exactly 'n' chars corresponding to a single Lua string. An absent 'n'
      means 1. When packing, the given string must have at least 'n' characters (extra
      characters are discarded).
    * `++c0++' this is like `++c++__n__', except that the 'n' is given by other means: When packing, 'n' is
      the length of the given string; when unpacking, 'n' is the value of the previous unpacked
      value (which must be a number). In that case, this previous value is not returned.
    * `++x++__n__' pad to 'n' number of bytes, default 1.
    * `++X++__n__' pad to 'n' alignment, default MAXALIGN.
    * `++(++' to stop assigning items, and `++)++' start assigning (padding when packing).
    * `++=++' to return the current position / offset.

  @note Using `i`, `I`, `h`, `H`, `l`, `L`, `f`, and `T` is strongly discouraged, as those sizes
    are system-dependent. Use the explicitly sized variants instead, such as `i4` or `E`.

  @note Unpacking of `i`/`I` is done to a Lua number, a double-precision floating point,
    so unpacking a 64-bit field (`i8`/`I8`) will lose precision.
    Use `e`/`E` to unpack into a Wireshark `Int64`/`UInt64` object instead.

  @since 1.11.3
 */


/* The following line is here so that make-reg.pl does the right thing.  This 'Struct' class
  isn't really a class, so it doesn't have the checkStruct/pushStruct/etc. functions
  the following macro would generate; but it does need to be registered and such, so...
  WSLUA_CLASS_DEFINE_BASE(Struct,NOP,0);
  */

/* basic integer type - yes this is system-specific size - it's meant to be */
#if !defined(STRUCT_INT)
#define STRUCT_INT  long
#endif

typedef STRUCT_INT Inttype;

/* corresponding unsigned version */
typedef unsigned STRUCT_INT Uinttype;

/* maximum size (in bytes) for integral types */
#define MAXINTSIZE  32

/* is 'x' a power of 2? */
#define isp2(x)  ((x) > 0 && ((x) & ((x) - 1)) == 0)

/* dummy structure to get padding/alignment requirements */
struct cD {
  gchar c;
  gdouble d;
};


#define PADDING         (sizeof(struct cD) - sizeof(gdouble))
#define MAXALIGN        (PADDING > sizeof(int) ? PADDING : sizeof(int))


/* endian options */
#define BIG     0
#define LITTLE  1

/* trick to determine native endianness of system */
static union {
  int dummy;
  gchar endian;
} const native = {1};

/* settings info */
typedef struct Header {
  int endian;
  int align;
  gboolean noassign;
} Header;

/* For options that take a number argument, gets the number  */
static int getnum (const gchar **fmt, int df) {
  if (!g_ascii_isdigit(**fmt))  /* no number? */
    return df;  /* return default value */
  else {
    int a = 0;
    do {
      a = a*10 + *((*fmt)++) - '0';
    } while (g_ascii_isdigit(**fmt));
    return a;
  }
}


#define defaultoptions(h)    ((h)->endian = native.endian, (h)->align = 1, (h)->noassign = FALSE)


/* gets size (number of bytes) for a given type */
static size_t optsize (lua_State *L, gchar opt, const gchar **fmt) {
  switch (opt) {
    case 'B': case 'b': return sizeof(gchar);
    case 'H': case 'h': return sizeof(gshort);
    case 'L': case 'l': return sizeof(glong);
    case 'E': case 'e': return sizeof(gint64);
    case 'T': return sizeof(size_t);
    case 'f': return sizeof(gfloat);
    case 'd': return sizeof(gdouble);
    case 'x': return getnum(fmt, 1);
    case 'X': return getnum(fmt, MAXALIGN);
    case 'c': return getnum(fmt, 1);
    case 'i': case 'I': {
      int sz = getnum(fmt, sizeof(int));
      if (sz > MAXINTSIZE)
        luaL_error(L, "integral size %d is larger than limit of %d",
                       sz, MAXINTSIZE);
      return sz;
    }
    case 's': case ' ':
    case '<': case '>':
    case '(': case ')':
    case '!': case '=':
              return 0;  /* these cases do not have a size */
    default: {
      const gchar *msg = lua_pushfstring(L, "invalid format option [%c]", opt);
      return luaL_argerror(L, 1, msg);
    }
  }
}


/*
** return number of bytes needed to align an element of size 'size'
** at current position 'len'
*/
static int gettoalign (size_t len, Header *h, int opt, size_t size) {
  if (size == 0 || opt == 'c' || opt == 's') return 0;
  if (size > (size_t)h->align)
    size = h->align;  /* respect max. alignment */
  return (int)((size - (len & (size - 1))) & (size - 1));
}


/*
** options to control endianness and alignment settings
*/
static void controloptions (lua_State *L, int opt, const gchar **fmt,
                            Header *h) {
  switch (opt) {
    case ' ': return;  /* ignore white spaces */
    case '>': h->endian = BIG; return;
    case '<': h->endian = LITTLE; return;
    case '(': h->noassign = TRUE; return;
    case ')': h->noassign = FALSE; return;
    case '!': {
      int a = getnum(fmt, MAXALIGN);
      if (!isp2(a))
        luaL_error(L, "alignment %d is not a power of 2", a);
      h->align = a;
      return;
    }
    default: {
      const char *msg = lua_pushfstring(L, "invalid format option '%c'", opt);
      luaL_argerror(L, 1, msg);
    }
  }
}

/* Encodes a Lua number as an integer of given size and endianness into a string struct */
static void putinteger (lua_State *L, luaL_Buffer *b, int arg, int endian,
                        int size) {
  lua_Number n = luaL_checknumber(L, arg);
  /* this one's not system dependent size - it's a long long */
  gint64 value;
  gchar buff[MAXINTSIZE];
  if (n < 0)
    value = (guint64)(gint64)n;
  else
    value = (guint64)n;
  if (endian == LITTLE) {
    int i;
    for (i = 0; i < size; i++) {
      buff[i] = (value & 0xff);
      value >>= 8;
    }
  }
  else {
    int i;
    for (i = size - 1; i >= 0; i--) {
      buff[i] = (value & 0xff);
      value >>= 8;
    }
  }
  luaL_addlstring(b, buff, size);
}

/* corrects endianness - usually done by other functions themselves, but is
 * used for float/doubles, since on some platforms they're endian'ed as well
 */
static void correctbytes (gchar *b, int size, int endian) {
  if (endian != native.endian) {
    int i = 0;
    while (i < --size) {
      gchar temp = b[i];
      b[i++] = b[size];
      b[size] = temp;
    }
  }
}


WSLUA_CONSTRUCTOR Struct_pack (lua_State *L) {
  /* Returns a string containing the values arg1, arg2, etc. packed/encoded according to the format string. */
#define WSLUA_ARG_Struct_pack_FORMAT 1 /* The format string */
#define WSLUA_ARG_Struct_pack_VALUE  2 /* One or more Lua value(s) to encode, based on the given format. */
  luaL_Buffer b;
  const char *fmt = wslua_checkstring_only(L, WSLUA_ARG_Struct_pack_FORMAT);
  Header h;
  int poscnt = 0;
  int posBuf[10];
  int arg = 2;
  size_t totalsize = 0;
  defaultoptions(&h);
  lua_pushnil(L);  /* mark to separate arguments from string buffer */
  luaL_buffinit(L, &b);
  while (*fmt != '\0') {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    int toalign = gettoalign(totalsize, &h, opt, size);
    totalsize += toalign;
    while (toalign-- > 0) luaL_addchar(&b, '\0');
    if (opt == 'X') size = 0; /* 'X' is about alignment, not size */
    if (h.noassign && size) opt = 'x'; /* for pack, "(i4)" is the same as "x4" */
    switch (opt) {
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'T': case 'i': case 'I': {  /* integer types */
        putinteger(L, &b, arg++, h.endian, (int)size);
        break;
      }
      case 'e': {
        Int64_pack(L, &b, arg++, h.endian == LITTLE);
        break;
      }
      case 'E': {
        UInt64_pack(L, &b, arg++, h.endian == LITTLE);
        break;
      }
      case 'x': case 'X': {
        size_t len = size;
        while (len-- > 0)
          luaL_addchar(&b, '\0');
        break;
      }
      case 'f': {
        gfloat f = (gfloat)luaL_checknumber(L, arg++);
        correctbytes((gchar *)&f, (int)size, h.endian);
        luaL_addlstring(&b, (gchar *)&f, size);
        break;
      }
      case 'd': {
        gdouble d = luaL_checknumber(L, arg++);
        correctbytes((gchar *)&d, (int)size, h.endian);
        luaL_addlstring(&b, (gchar *)&d, size);
        break;
      }
      case 'c': case 's': {
        size_t l;
        const gchar *s = luaL_checklstring(L, arg++, &l);
        if (size == 0) size = l;
        luaL_argcheck(L, l >= (size_t)size, arg, "string too short");
        luaL_addlstring(&b, s, size);
        if (opt == 's') {
          luaL_addchar(&b, '\0');  /* add zero at the end */
          size++;
        }
        break;
      }
      case '=': {
        if (poscnt < (int)(sizeof(posBuf)/sizeof(posBuf[0])))
          posBuf[poscnt++] = (int)totalsize + 1;
        break;
      }
      default: controloptions(L, opt, &fmt, &h);
    }
    totalsize += size;
  }
  luaL_pushresult(&b);
  for (arg = 0; arg < poscnt; arg++)
    lua_pushinteger(L, posBuf[arg]);
  WSLUA_RETURN(poscnt + 1); /* The packed binary Lua string, plus any positions due to '=' being used in format. */
}

/* Decodes an integer from a string struct into a Lua number, based on
 * given endianness and size. If the integer type is signed, this makes
 * the Lua number be +/- correctly as well.
 */
static lua_Number getinteger (const gchar *buff, int endian,
                        int issigned, int size) {
  Uinttype l = 0;
  int i;
  if (endian == BIG) {
    for (i = 0; i < size; i++) {
      l <<= 8;
      l |= (Uinttype)(guchar)buff[i];
    }
  }
  else {
    for (i = size - 1; i >= 0; i--) {
      l <<= 8;
      l |= (Uinttype)(guchar)buff[i];
    }
  }
  if (!issigned)
    return (lua_Number)l;
  else {  /* signed format */
    Uinttype mask = (Uinttype)(~((Uinttype)0)) << (size*8 - 1);
    if (l & mask)  /* negative value? */
      l |= mask;  /* signal extension */
    return (lua_Number)(Inttype)l;
  }
}

#define b_pushnumber(n) { if (!h.noassign) lua_pushnumber(L, (lua_Number)(n)); }

WSLUA_CONSTRUCTOR Struct_unpack (lua_State *L) {
  /*  Unpacks/decodes multiple Lua values from a given struct-like binary Lua string.
      The number of returned values depends on the format given, plus an additional value of the position where it stopped reading is returned. */
#define WSLUA_ARG_Struct_unpack_FORMAT 1 /* The format string */
#define WSLUA_ARG_Struct_unpack_STRUCT 2 /* The binary Lua string to unpack */
#define WSLUA_OPTARG_Struct_unpack_BEGIN  3 /* The position to begin reading from (default=1) */
  Header h;
  const char *fmt = wslua_checkstring_only(L, WSLUA_ARG_Struct_unpack_FORMAT);
  size_t ld;
  const char *data = wslua_checklstring_only(L, WSLUA_ARG_Struct_unpack_STRUCT, &ld);
  size_t pos = luaL_optinteger(L, WSLUA_OPTARG_Struct_unpack_BEGIN, 1) - 1;
  defaultoptions(&h);
  lua_settop(L, 2);
  while (*fmt) {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    pos += gettoalign(pos, &h, opt, size);
    luaL_argcheck(L, pos+size <= ld, 2, "data string too short");

    if (opt == 'X') size = 0;
    if (h.noassign && size > 0) {
      /* if we're not assigning, and the opt type has a size, then loop again */
      /* this will not be the case for control options, 'c0', 's', and '=' */
      pos += size;
      continue;
    }

    luaL_checkstack(L, 1, "too many results");
    switch (opt) {
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'T': case 'i':  case 'I': {  /* integer types */
        int issigned = g_ascii_islower(opt);
        lua_Number res = getinteger(data+pos, h.endian, issigned, (int)size);
        lua_pushnumber(L, res);
        break;
      }
      case 'e': {
        Int64_unpack(L, data+pos, h.endian == LITTLE);
        break;
      }
      case 'E': {
        UInt64_unpack(L, data+pos, h.endian == LITTLE);
        break;
      }
      case 'x': case 'X': {
        break;
      }
      case 'f': {
        gfloat f;
        memcpy(&f, data+pos, size);
        correctbytes((gchar *)&f, sizeof(f), h.endian);
        lua_pushnumber(L, f);
        break;
      }
      case 'd': {
        gdouble d;
        memcpy(&d, data+pos, size);
        correctbytes((gchar *)&d, sizeof(d), h.endian);
        lua_pushnumber(L, d);
        break;
      }
      case 'c': {
        if (size == 0) {
          if (!lua_isnumber(L, -1))
            luaL_error(L, "format `c0' needs a previous size");
          size = wslua_toguint32(L, -1);
          lua_pop(L, 1);
          luaL_argcheck(L, pos+size <= ld, 2, "data string too short");
        }
        if (!h.noassign)
          lua_pushlstring(L, data+pos, size);
        break;
      }
      case 's': {
        const gchar *e = (const char *)memchr(data+pos, '\0', ld - pos);
        if (e == NULL)
          luaL_error(L, "unfinished string in data");
        size = (e - (data+pos)) + 1;
        if (!h.noassign)
          lua_pushlstring(L, data+pos, size - 1);
        break;
      }
      case '=': {
        lua_pushinteger(L, pos + 1);
        break;
      }
      default: controloptions(L, opt, &fmt, &h);
    }
    pos += size;
  }
  lua_pushinteger(L, pos + 1);
  WSLUA_RETURN(lua_gettop(L) - 2); /* One or more values based on format, plus the position it stopped unpacking. */
}


WSLUA_CONSTRUCTOR Struct_size (lua_State *L) {
  /* Returns the length of a binary string that would be consumed/handled by the given format string. */
#define WSLUA_ARG_Struct_size_FORMAT 1 /* The format string */
  Header h;
  const gchar *fmt = wslua_checkstring_only(L, WSLUA_ARG_Struct_size_FORMAT);
  size_t pos = 0;
  defaultoptions(&h);
  while (*fmt) {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    pos += gettoalign(pos, &h, opt, size);
    if (opt == 's')
      luaL_argerror(L, 1, "option 's' has no fixed size");
    else if (opt == 'c' && size == 0)
      luaL_argerror(L, 1, "option 'c0' has no fixed size");
    if (!g_ascii_isalnum(opt))
      controloptions(L, opt, &fmt, &h);
    pos += size;
  }
  lua_pushinteger(L, pos);
  WSLUA_RETURN(1); /* The size number */
}

WSLUA_CONSTRUCTOR Struct_values (lua_State *L) {
  /* Returns the number of Lua values contained in the given format string.
     This will be the number of returned values from a call to Struct.unpack()
     not including the extra return value of offset position. (i.e., Struct.values()
     does not count that extra return value) This will also be the number of
     arguments Struct.pack() expects, not including the format string argument. */
#define WSLUA_ARG_Struct_values_FORMAT 1 /* The format string */
  Header h;
  const gchar *fmt = wslua_checkstring_only(L, WSLUA_ARG_Struct_values_FORMAT);
  size_t vals = 0;
  defaultoptions(&h);
  while (*fmt) {
    int opt = *fmt++;
    /* we use a size != 0 to mean it is a value */
    size_t size = optsize(L, opt, &fmt);
    /* but some will be zero and not be a value, or vice-versa */
    switch (opt) {
      case 's': case 'c':
        /* these are values */
        size = 1;
        break;
      case 'x': case 'X':
        /* these are not */
        size = 0;
        break;
      default:
        break;
    }
    if (!g_ascii_isalnum(opt))
      controloptions(L, opt, &fmt, &h);
    else if (size && !h.noassign)
      vals++;
  }
  lua_pushinteger(L, vals);
  WSLUA_RETURN(1); /* The number of values */
}

WSLUA_CONSTRUCTOR Struct_tohex (lua_State *L) {
  /* Converts the passed-in binary string to a hex-ascii string. */
#define WSLUA_ARG_Struct_tohex_BYTESTRING 1 /* A Lua string consisting of binary bytes */
#define WSLUA_OPTARG_Struct_tohex_LOWERCASE 2 /* True to use lower-case hex characters (default=false). */
#define WSLUA_OPTARG_Struct_tohex_SEPARATOR 3 /* A string separator to insert between hex bytes (default=nil). */
  const gchar* s = NULL;
  size_t len = 0;
  gboolean lowercase = FALSE;
  const gchar* sep = NULL;

  /* luaL_checklstring coerces the argument to a string, and that's ok for tohex,
     just not fromhex. In fact, we should accept/coerce a Int64/UInt64 here too someday. */
  s = luaL_checklstring(L, WSLUA_ARG_Struct_tohex_BYTESTRING, &len);

  lowercase = wslua_optbool(L,WSLUA_OPTARG_Struct_tohex_LOWERCASE,FALSE);
  sep = luaL_optstring(L,WSLUA_OPTARG_Struct_tohex_SEPARATOR,NULL);

  wslua_bin2hex(L, s, (guint)len, lowercase, sep);
  WSLUA_RETURN(1); /* The Lua hex-ascii string */
}

WSLUA_CONSTRUCTOR Struct_fromhex (lua_State *L) {
  /* Converts the passed-in hex-ascii string to a binary string. */
#define WSLUA_ARG_Struct_fromhex_HEXBYTES 1 /* A string consisting of hexadecimal bytes like "00 B1 A2" or "1a2b3c4d" */
#define WSLUA_OPTARG_Struct_fromhex_SEPARATOR 2 /* A string separator between hex bytes/words (default=" "). */
  const gchar* s = NULL;
  size_t len = 0;
  const gchar* sep = NULL;

  /* luaL_checklstring coerces the argument to a string, and we don't want to do that */
  s = wslua_checklstring_only(L, WSLUA_ARG_Struct_fromhex_HEXBYTES, &len);

  sep = luaL_optstring(L,WSLUA_OPTARG_Struct_fromhex_SEPARATOR,NULL);

  wslua_hex2bin(L, s, (guint)len, sep);
  WSLUA_RETURN(1); /* The Lua binary string */
}

/* }====================================================== */

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Struct__gc(lua_State* L _U_) {
    return 0;
}

WSLUA_METHODS Struct_methods[] = {
  WSLUA_CLASS_FNREG(Struct,pack),
  WSLUA_CLASS_FNREG(Struct,unpack),
  WSLUA_CLASS_FNREG(Struct,size),
  WSLUA_CLASS_FNREG(Struct,values),
  WSLUA_CLASS_FNREG(Struct,tohex),
  WSLUA_CLASS_FNREG(Struct,fromhex),
  { NULL, NULL }
};

WSLUA_META Struct_meta[] = {
    { NULL, NULL }
};

LUALIB_API int Struct_register(lua_State* L) {
  WSLUA_REGISTER_CLASS(Struct);
  return 0;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
