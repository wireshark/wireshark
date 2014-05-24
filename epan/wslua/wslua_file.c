/*
 * wslua_file.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for custom file format reading/writing.
 *
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "wslua.h"
#include <errno.h>
#include <wiretap/wtap-int.h>
#include <wiretap/file_wrappers.h>
#include <epan/addr_resolv.h>
#include <math.h>

#define MAX_LINE_LENGTH            65536

/* WSLUA_MODULE File Custom file format reading/writing

   The classes/functions defined in this section allow you to create your own
   custom Lua-based "capture" file reader, or writer, or both.

   @since 1.11.3
 */


WSLUA_CLASS_DEFINE(File,FAIL_ON_NULL_OR_EXPIRED("File"),NOP);
/*
    A `File` object, passed into Lua as an argument by FileHandler callback
    functions (e.g., `read_open`, `read`, `write`, etc.).  This behaves similarly to the
    Lua `io` library's `file` object, returned when calling `io.open()`, *except*
    in this case you cannot call `file:close()`, `file:open()`, nor `file:setvbuf()`,
    since Wireshark/tshark manages the opening and closing of files.
    You also cannot use the '`io`' library itself on this object, i.e. you cannot
    do `io.read(file, 4)`.  Instead, use this `File` with the object-oriented style
    calling its methods, i.e. `myfile:read(4)`. (see later example)

    The purpose of this object is to hide the internal complexity of how Wireshark
    handles files, and instead provide a Lua interface that is familiar, by mimicking
    the `io` library. The reason true/raw `io` files cannot be used is because Wireshark
    does many things under the hood, such as compress the file, or write to `stdout`,
    or various other things based on configuration/commands.

    When a `File` object is passed in through reading-based callback functions, such as
    `read_open()`, `read()`, and `read_close()`, then the File object's `write()` and `flush()`
    functions are not usable and will raise an error if used.

    When a `File` object is passed in through writing-based callback functions, such as
    `write_open()`, `write()`, and `write_close()`, then the File object's `read()` and `lines()`
    functions are not usable and will raise an error if used.

    Note: a `File` object should never be stored/saved beyond the scope of the callback function
    it is passed in to.

    For example:
    @code
    function myfilehandler.read_open(file, capture)
        local position = file:seek()

        -- read 24 bytes
        local line = file:read(24)

        -- do stuff

        -- it's not our file type, seek back (unnecessary but just to show it...)
        file:seek("set",position)

        -- return false because it's not our file type
        return false
    end
    @endcode

   @since 1.11.3
 */


/* a "File" object can be different things under the hood. It can either
   be a FILE_T from wtap struct, which it is during read operations, or it
   can be a wtap_dumper struct during write operations. A wtap_dumper struct
   has a FILE_T member, but we can't only store its pointer here because
   dump operations need the whole thing to write out with. Ugh. */
static File* push_File(lua_State* L, FILE_T ft) {
    File f = (File) g_malloc(sizeof(struct _wslua_file));
    f->file = ft;
    f->wdh = NULL;
    f->expired = FALSE;
    return pushFile(L,f);
}

static File* push_Wdh(lua_State* L, wtap_dumper *wdh) {
    File f = (File) g_malloc(sizeof(struct _wslua_file));
    f->file = (FILE_T)wdh->fh;
    f->wdh = wdh;
    f->expired = FALSE;
    return pushFile(L,f);
}

static gboolean file_is_reader(File f) {
    return (f->wdh == NULL);
}

/* This internal function reads a number from the file, similar to Lua's io.read("*num").
 * In Lua this is done with a fscanf(file, "%lf", &double), but we can't use fscanf() since
 * this may be coming from a zip file and we need to use file_wrappers.c functions.
 * So we get a character at a time, building a buffer for fscanf.
 * XXX this isn't perfect - if just "2." exists in file, for example, it consumes it.
 */
#define WSLUA_MAXNUMBER2STR  32 /* 16 digits, sign, point, and \0 */
static int File_read_number (lua_State *L, FILE_T ft) {
    lua_Number d;
    gchar buff[WSLUA_MAXNUMBER2STR];
    int buff_end = 0;
    int c = -1;
    int num_digits = 0;
    gboolean has_decimal = FALSE;

    c = file_peekc(ft);
    if (c == '+' || c == '-') {
        buff[buff_end++] = (gchar)c;
        /* make sure next char is a digit */
        c = file_peekc(ft);
        if (c < '0' || c > '9') {
            lua_pushnil(L);  /* "result" to be removed */
            return 0;  /* read fails */
        }
        /* eat the +/- */
        file_getc(ft);
    }

    while((c = file_peekc(ft)) > 0 && buff_end < (WSLUA_MAXNUMBER2STR-1)) {
        if (c >= '0' && c <= '9') {
            buff[buff_end++] = (gchar)c;
            num_digits++;
            file_getc(ft);
        }
        else if (!has_decimal && c == '.') {
            has_decimal = TRUE;
            buff[buff_end++] = (gchar)c;
            file_getc(ft);
        }
        else break;
    }

    buff[buff_end] = '\0';

    if (buff_end > 0 && num_digits > 0 && sscanf(buff, "%lf", &d) == 1) {
        lua_pushnumber(L, d);
        return 1;
    }
    else {
        lua_pushnil(L);  /* "result" to be removed */
        return 0;  /* read fails */
    }
}

static int File_read_line(lua_State *L, FILE_T ft) {
    static gchar linebuff[MAX_LINE_LENGTH];
    gint64 pos_before = file_tell(ft);
    gint length = 0;

    if (file_gets(linebuff, MAX_LINE_LENGTH, ft) == NULL) {
        /* No characters found, or error */
        /* *err = file_error(ft, err_info); */
        return 0;
    }

    /* Set length (avoiding strlen()) */
    length = (gint)(file_tell(ft) - pos_before);

    /* ...but don't want to include newline in line length */
    if (linebuff[length-1] == '\n') {
        length--;
        /* Nor do we want '\r' (as will be written when log is created on windows) */
        if (length > 0 && linebuff[length - 1] == '\r') {
            length--;
        }
        linebuff[length] = '\0';
    }

    lua_pushlstring(L, linebuff, length);
    return 1;
}

/* This internal function reads X number of bytes from the file, same as `io.read(num)` in Lua.
 * Since we have to use file_wrappers.c, and an intermediate buffer, we read it in chunks
 * of 1024 bytes at a time. (or less if called with a smaller number)  To do that, we use
 * Lua's buffer manager to push it into Lua as those chunks, while ending up with one long
 * Lua string in the end.
 */
#define WSLUA_BUFFERSIZE 1024

/* Lua 5.1 used lua_objlen() instead of lua_rawlen() */
#if LUA_VERSION_NUM == 501
#define lua_rawlen lua_objlen
#endif

static int File_read_chars(lua_State *L, FILE_T ft, size_t n) {
    size_t rlen;  /* how much to read */
    size_t nr;  /* number of chars actually read */
    int    nri; /* temp number of chars read, as an int to handle -1 errors */
    gchar buff[WSLUA_BUFFERSIZE];  /* for file_read to write to, and we push into Lua */
    luaL_Buffer b;

    rlen = WSLUA_BUFFERSIZE;  /* try to read that much each time */
    luaL_buffinit(L, &b); /* initialize Lua buffer */

    do {
        if (rlen > n) rlen = n;  /* cannot read more than asked */
        nri = file_read(buff, (unsigned int)rlen, ft);
        if (nri < 1) break;
        nr = (size_t) nri;
        luaL_addlstring(&b, buff, nr);
        n -= nr;  /* still have to read `n' chars */
    } while (n > 0 && nr == rlen);  /* until end of count or eof */

    luaL_pushresult(&b);  /* close buffer */

    return (n == 0 || lua_rawlen(L, -1) > 0);
}

/* returns nil if EOF, else an empty string - this is what Lua does too for this case */
static int File_test_eof(lua_State *L, FILE_T ft) {
    if (file_eof(ft)) {
        lua_pushnil(L);
    }
    else {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

static int pushresult (lua_State *L, int i, const char *filename) {
  int en = errno;  /* calls to Lua API may change this value, so we save it */
  if (i) {
    lua_pushboolean(L, 1);
    return 1;
  }
  else {
    lua_pushnil(L);
    if (filename)
      lua_pushfstring(L, "%s: %s", filename, g_strerror(en));
    else
      lua_pushfstring(L, "%s", g_strerror(en));
    lua_pushinteger(L, en);
    return 3;
  }
}

WSLUA_METHOD File_read(lua_State* L) {
    /* Reads from the File, similar to Lua's `file:read()`.  See Lua 5.x ref manual for `file:read()`. */
    File f = shiftFile(L,1);
    int nargs = lua_gettop(L);
    int success;
    int n = 1;
    FILE_T ft = NULL;

    if (!f || !f->file) {
        return 0;
    }

    /* shiftFile() doesn't verify things like expired */
    if (f->expired) {
        g_warning("Error in File read: Lua File has expired");
        return 0;
    }

    if (!file_is_reader(f)) {
        g_warning("Error in File read: this File object instance is for writing only");
        return 0;
    }

    ft = f->file;

    /* file_clearerr(ft); */
    if (nargs == 0) {  /* no arguments? */
        success = File_read_line(L, ft);
        n = 2;  /* to return 1 result */
    }
    else {  /* ensure stack space for all results and Lua */
        luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
        success = 1;
        for (n = 1; nargs-- && success; n++) {
            if (lua_type(L, n) == LUA_TNUMBER) {
                size_t l = (size_t)lua_tointeger(L, n);
                success = (l == 0) ? File_test_eof(L, ft) : File_read_chars(L, ft, l);
            }
            else {
                const char *p = lua_tostring(L, n);
                if (!p) return luaL_argerror(L, n, "invalid format argument");
                luaL_argcheck(L, p[0] == '*', n, "invalid option");
                switch (p[1]) {
                    case 'n':  /* number */
                        success = File_read_number(L, ft);
                        break;
                    case 'l':  /* line */
                        success = File_read_line(L, ft);
                        break;
                    case 'a':  /* file, read everything */
                        File_read_chars(L, ft, ~((size_t)0));  /* read MAX_SIZE_T chars */
                        success = 1; /* always success */
                        break;
                    default:
                        return luaL_argerror(L, n, "invalid format");
                }
            }
        }
    }
    if (file_error(ft, NULL))
        return pushresult(L, 0, NULL);
    if (!success) {
        lua_pop(L, 1);  /* remove last result */
        lua_pushnil(L);  /* push nil instead */
    }
    return n - 1;
}

WSLUA_METHOD File_seek(lua_State* L) {
    /* Seeks in the File, similar to Lua's `file:seek()`.  See Lua 5.x ref manual for `file:seek()`. */
    static const int mode[] = { SEEK_SET, SEEK_CUR, SEEK_END };
    static const char *const modenames[] = {"set", "cur", "end", NULL};
    File f = checkFile(L,1);
    int op = luaL_checkoption(L, 2, "cur", modenames);
    gint64 offset = (gint64) luaL_optlong(L, 3, 0);
    int err = WTAP_ERR_INTERNAL;


    if (file_is_reader(f)) {
        offset = file_seek(f->file, offset, mode[op], &err);

        if (offset < 0) {
            lua_pushnil(L);  /* error */
            lua_pushstring(L, wtap_strerror(err));
            return 2;
        }

        lua_pushnumber(L, (lua_Number)(file_tell(f->file)));
    }
    else {
        offset = wtap_dump_file_seek(f->wdh, offset, mode[op], &err);

        if (offset < 0) {
            lua_pushnil(L);  /* error */
            lua_pushstring(L, wtap_strerror(err));
            return 2;
        }

        offset = wtap_dump_file_tell(f->wdh, &err);

        if (offset < 0) {
            lua_pushnil(L);  /* error */
            lua_pushstring(L, wtap_strerror(err));
            return 2;
        }

        lua_pushnumber(L, (lua_Number)(offset));
    }

    WSLUA_RETURN(1); /* The current file cursor position as a number. */
}

static int File_lines_iterator(lua_State* L) {
    FILE_T ft = *(FILE_T *)lua_touserdata(L, lua_upvalueindex(1));
    int success;

    if (ft == NULL)
        return luaL_error(L, "Error getting File handle for lines iterator");

    success = File_read_line(L, ft);

    /* if (ferror(ft))
        return luaL_error(L, "%s", g_strerror(errno));
    */
    return success;
}

WSLUA_METHOD File_lines(lua_State* L) {
    /* Lua iterator function for retrieving ASCII File lines, similar to Lua's `file:lines()`.  See Lua 5.x ref manual for `file:lines()`. */
    File f = checkFile(L,1);
    FILE_T ft = NULL;

    if (!f->file)
        return luaL_error(L, "Error getting File handle for lines");

    if (!file_is_reader(f)) {
        g_warning("Error in File read: this File object instance is for writing only");
        return 0;
    }

    ft = f->file;

    lua_pushlightuserdata(L, ft);
    lua_pushcclosure(L, File_lines_iterator, 1);

    return 1;
}

/* yeah this function is a little weird, but I'm mimicking Lua's actual code for io:write() */
WSLUA_METHOD File_write(lua_State* L) {
    /* Writes to the File, similar to Lua's file:write().  See Lua 5.x ref manual for file:write(). */
    File f = checkFile(L,1);
    int arg = 2;                   /* beginning index for arguments */
    int nargs = lua_gettop(L) - 1;
    int status = TRUE;
    int err = 0;

    if (!f->wdh) {
        g_warning("Error in File read: this File object instance is for reading only");
        return 0;
    }

    lua_pushvalue(L, 1);  /* push File at the stack top (to be returned) */

    for (; nargs--; arg++) {
        size_t len;
        const char *s = luaL_checklstring(L, arg, &len);
        status = wtap_dump_file_write(f->wdh, s, len, &err);
        if (!status) break;
        f->wdh->bytes_dumped += len;
    }

    if (!status) {
        lua_pop(L,1); /* pop the extraneous File object */
        lua_pushnil(L);
        lua_pushfstring(L, "File write error: %s", g_strerror(err));
        lua_pushinteger(L, err);
        return 3;
    }

    return 1;  /* File object already on stack top */
}

WSLUA_METAMETHOD File__tostring(lua_State* L) {
    /* Generates a string of debug info for the File object */
    File f = toFile(L,1);

    if (!f) {
        lua_pushstring(L,"File pointer is NULL!");
    } else {
        lua_pushfstring(L,"File expired=%s, handle=%s, is %s", f->expired? "true":"false", f->file? "<ptr>":"<NULL>",
            f->wdh? "writer":"reader");
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

/* We free the struct we malloc'ed, but not the FILE_T/dumper in it of course */
static int File__gc(lua_State* L _U_) {
    File f = toFile(L,1);
    if (f)
        g_free(f);
    return 0;
}

/* WSLUA_ATTRIBUTE File_compressed RO Whether the File is compressed or not.

    See `wtap_encaps` in init.lua for available types.  Set to `wtap_encaps.PER_PACKET` if packets can
    have different types, then later set `FrameInfo.encap` for each packet during read()/seek_read(). */
static int File_get_compressed(lua_State* L) {
    File f = checkFile(L,1);

    if (file_is_reader(f)) {
        lua_pushboolean(L, file_iscompressed(f->file));
    } else {
        lua_pushboolean(L, f->wdh->compressed);
    }
    return 1;
}

WSLUA_ATTRIBUTES File_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(File,compressed),
    { NULL, NULL, NULL }
};

WSLUA_METHODS File_methods[] = {
    WSLUA_CLASS_FNREG(File,lines),
    WSLUA_CLASS_FNREG(File,read),
    WSLUA_CLASS_FNREG(File,seek),
    WSLUA_CLASS_FNREG(File,write),
    { NULL, NULL }
};

WSLUA_META File_meta[] = {
    WSLUA_CLASS_MTREG(File,tostring),
    { NULL, NULL }
};

int File_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(File);
    WSLUA_REGISTER_ATTRIBUTES(File);
    return 0;
}


/************
 * The following is for handling private data for the duration of the file
 * read_open/read/close cycle, or write_open/write/write_close cycle.
 * In other words it handles the "priv" member of wtap and wtap_dumper,
 * but for the Lua script's use. A Lua script can set a Lua table
 * to CaptureInfo/CaptureInfoConst and have it saved and retrievable this way.
 * We need to offer that, because there needs to be a way for Lua scripts
 * to save state for a given file's operations cycle. Since there can be
 * two files opened at the same time for the same Lua script (due to reload
 * and other such events), the script can't just have one file state.
 */

/* this is way overkill for this one member, but in case we need to add
   more in the future, the plumbing will be here */
typedef struct _file_priv_t {
    int table_ref;
} file_priv_t;

/* create and set the wtap->priv private data for the file instance */
static void create_wth_priv(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*)g_malloc(sizeof(file_priv_t));

    if (wth->priv != NULL) {
        luaL_error(L, "Cannot create wtap private data because there already is private data");
        return;
    }
    priv->table_ref = LUA_NOREF;
    wth->priv = (void*) priv;
}

/* gets the private data table from wtap */
static int get_wth_priv_table_ref(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return LUA_NOREF;
    }

    /* the following might push a nil, but that's ok */
    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->table_ref);

    return 1;
}

/* sets the private data to wtap - the table is presumed on top of stack */
static int set_wth_priv_table_ref(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return 0;
    }

    if (lua_isnil(L, -1)){
        /* user is setting it nil - ok, de-ref any previous one */
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
        priv->table_ref = LUA_NOREF;
        return 0;
    }

    if (!lua_istable(L, -1)) {
        luaL_error(L, "The private_table member can only be set to a table or nil");
        return 0;
    }

    /* if we had a table already referenced, de-ref it first */
    if (priv->table_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    }

    priv->table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* remove, deref, and free the wtap->priv data */
static void remove_wth_priv(lua_State* L, wtap *wth) {
    file_priv_t *priv = (file_priv_t*) wth->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot remove wtap private data: it is null");
        return;
    }

    luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);

    g_free(wth->priv);
    wth->priv = NULL;
}

/* create and set the wtap_dumper->priv private data for the file instance */
static void create_wdh_priv(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*)g_malloc(sizeof(file_priv_t));

    if (wdh->priv != NULL) {
        luaL_error(L, "Cannot create wtap_dumper private data because there already is private data");
        return;
    }
    priv->table_ref = LUA_NOREF;
    wdh->priv = (void*) priv;
}

/* get the private data from wtap_dumper */
static int get_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap_dumper private data: it is null");
        return LUA_NOREF;
    }

    /* the following might push a nil, but that's ok */
    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->table_ref);

    return 1;
}

/* sets the private data to wtap - the table is presumed on top of stack */
static int set_wdh_priv_table_ref(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot get wtap private data: it is null");
        return 0;
    }

    if (lua_isnil(L, -1)){
        /* user is setting it nil - ok, de-ref any previous one */
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
        priv->table_ref = LUA_NOREF;
        return 0;
    }

    if (!lua_istable(L, -1)) {
        luaL_error(L, "The private_table member can only be set to a table or nil");
        return 0;
    }

    /* if we had a table already referenced, de-ref it first */
    if (priv->table_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    }

    priv->table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* remove and deref the wtap_dumper->priv data */
static void remove_wdh_priv(lua_State* L, wtap_dumper *wdh) {
    file_priv_t *priv = (file_priv_t*) wdh->priv;

    if (!priv) {
        /* shouldn't be possible */
        luaL_error(L, "Cannot remove wtap_dumper private data: it is null");
        return;
    }

    luaL_unref(L, LUA_REGISTRYINDEX, priv->table_ref);
    /* we do NOT free wtap_dumper's priv member - wtap_dump_close() free's it */
}


WSLUA_CLASS_DEFINE(CaptureInfo,FAIL_ON_NULL_MEMBER_OR_EXPIRED("CaptureInfo",wth),NOP);
/*
    A `CaptureInfo` object, passed into Lua as an argument by `FileHandler` callback
    function `read_open()`, `read()`, `seek_read()`, `seq_read_close()`, and `read_close()`.
    This object represents capture file data and meta-data (data about the
    capture file) being read into Wireshark/Tshark.

    This object's fields can be written-to by Lua during the read-based function callbacks.
    In other words, when the Lua plugin's `FileHandler.read_open()` function is invoked, a
    `CaptureInfo` object will be passed in as one of the arguments, and its fields
    should be written to by your Lua code to tell Wireshark about the capture.

    @since 1.11.3
 */

static CaptureInfo* push_CaptureInfo(lua_State* L, wtap *wth, const gboolean first_time) {
    CaptureInfo f = (CaptureInfo) g_malloc0(sizeof(struct _wslua_captureinfo));
    f->wth = wth;
    f->wdh = NULL;
    f->expired = FALSE;

    if (first_time) {
        /* XXX: need to do this? */
        wth->file_encap = WTAP_ENCAP_UNKNOWN;
        wth->tsprecision = WTAP_FILE_TSPREC_SEC;
        wth->snapshot_length = 0;
    }

    return pushCaptureInfo(L,f);
}

WSLUA_METAMETHOD CaptureInfo__tostring(lua_State* L) {
    /* Generates a string of debug info for the CaptureInfo */
    CaptureInfo fi = toCaptureInfo(L,1);

    if (!fi || !fi->wth) {
        lua_pushstring(L,"CaptureInfo pointer is NULL!");
    } else {
        wtap *wth = fi->wth;
        lua_pushfstring(L, "CaptureInfo: file_type_subtype=%d, snapshot_length=%d, pkt_encap=%d, tsprecision='%s'",
            wth->file_type_subtype, wth->snapshot_length, wth->phdr.pkt_encap, wth->tsprecision);
    }

    WSLUA_RETURN(1); /* String of debug information. */
}


static int CaptureInfo__gc(lua_State* L _U_) {
    CaptureInfo fc = toCaptureInfo(L,1);
    if (fc)
        g_free(fc);
    return 0;
}

/* WSLUA_ATTRIBUTE CaptureInfo_encap RW The packet encapsulation type for the whole file.

    See `wtap_encaps` in `init.lua` for available types.  Set to `wtap_encaps.PER_PACKET` if packets can
    have different types, then later set `FrameInfo.encap` for each packet during `read()`/`seek_read()`.
 */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfo,encap,wth->file_encap);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(CaptureInfo,encap,wth->file_encap,int);

/* WSLUA_ATTRIBUTE CaptureInfo_time_precision RW The precision of the packet timestamps in the file.

    See `wtap_file_tsprec` in `init.lua` for available precisions.
 */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfo,time_precision,wth->tsprecision);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(CaptureInfo,time_precision,wth->tsprecision,int);

/* WSLUA_ATTRIBUTE CaptureInfo_snapshot_length RW The maximum packet length that could be recorded.

    Setting it to `0` means unknown.  Wireshark cannot handle anything bigger than 65535 bytes.
 */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfo,snapshot_length,wth->snapshot_length);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(CaptureInfo,snapshot_length,wth->snapshot_length,guint);

/* WSLUA_ATTRIBUTE CaptureInfo_comment RW A string comment for the whole capture file,
    or nil if there is no `comment`. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfo,comment,wth->shb_hdr.opt_comment);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(CaptureInfo,comment,wth->shb_hdr.opt_comment,TRUE);

/* WSLUA_ATTRIBUTE CaptureInfo_hardware RW A string containing the description of
    the hardware used to create the capture, or nil if there is no `hardware` string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfo,hardware,wth->shb_hdr.shb_hardware);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(CaptureInfo,hardware,wth->shb_hdr.shb_hardware,TRUE);

/* WSLUA_ATTRIBUTE CaptureInfo_os RW A string containing the name of
    the operating system used to create the capture, or nil if there is no `os` string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfo,os,wth->shb_hdr.shb_os);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(CaptureInfo,os,wth->shb_hdr.shb_os,TRUE);

/* WSLUA_ATTRIBUTE CaptureInfo_user_app RW A string containing the name of
    the application used to create the capture, or nil if there is no `user_app` string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfo,user_app,wth->shb_hdr.shb_user_appl);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(CaptureInfo,user_app,wth->shb_hdr.shb_user_appl,TRUE);

/* WSLUA_ATTRIBUTE CaptureInfo_hosts WO Sets resolved ip-to-hostname information.

    The value set must be a Lua table of two key-ed names: `ipv4_addresses` and `ipv6_addresses`.
    The value of each of these names are themselves array tables, of key-ed tables, such that the inner table has a key
    `addr` set to the raw 4-byte or 16-byte IP address Lua string and a `name` set to the resolved name.

    For example, if the capture file identifies one resolved IPv4 address of 1.2.3.4 to `foo.com`, then you must set
    `CaptureInfo.hosts` to a table of:
    @code { ipv4_addresses = { { addr = "\01\02\03\04", name = "foo.com" } } } @endcode

    Note that either the `ipv4_addresses` or the `ipv6_addresses` table, or both, may be empty or nil.
    */
static int CaptureInfo_set_hosts(lua_State* L) {
    CaptureInfo fi = checkCaptureInfo(L,1);
    wtap *wth = fi->wth;
    const char *addr = NULL;
    const char *name = NULL;
    size_t addr_len = 0;
    size_t name_len = 0;
    guint32 v4_addr = 0;
    struct e_in6_addr v6_addr = { {0} };

    if (!wth->add_new_ipv4 || !wth->add_new_ipv6) {
        return luaL_error(L, "CaptureInfo wtap has no IPv4 or IPv6 name resolution");
    }

    if (!lua_istable(L,-1)) {
        return luaL_error(L, "CaptureInfo.host must be set to a table");
    }

    /* get the ipv4_addresses table */
    lua_getfield(L, -1, "ipv4_addresses");

    if (lua_istable(L,-1)) {
        /* now walk the table */
        lua_pushnil(L);  /* first key */
        while (lua_next(L, -2) != 0) {
            /* 'key' (at index -2) and 'value' (at index -1) */
            if (!lua_istable(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv4_addresses table does not contain a table");
            }

            lua_getfield(L, -1, "addr");
            if (!lua_isstring(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv4_addresses table's table does not contain an 'addr' field");
            }
            addr = luaL_checklstring(L,-1,&addr_len);
            if (addr_len != 4) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv4_addresses 'addr' value is not 4 bytes long");
            }
            memcpy(&v4_addr, addr, 4);

            lua_getfield(L, -1, "name");
            if (!lua_isstring(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv4_addresses table's table does not contain an 'addr' field");
            }
            name = luaL_checklstring(L,-1,&name_len);

            wth->add_new_ipv4(v4_addr, name);

            /* removes 'value'; keeps 'key' for next iteration */
            lua_pop(L, 1);
        }
    }

    /* wasn't a table, or it was and we walked it; either way pop it */
    lua_pop(L,1);


     /* get the ipv6_addresses table */
    lua_getfield(L, -1, "ip6_addresses");

    if (lua_istable(L,-1)) {
        /* now walk the table */
        lua_pushnil(L);  /* first key */
        while (lua_next(L, -2) != 0) {
            /* 'key' (at index -2) and 'value' (at index -1) */
            if (!lua_istable(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv6_addresses table does not contain a table");
            }

            lua_getfield(L, -1, "addr");
            if (!lua_isstring(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv6_addresses table's table does not contain an 'addr' field");
            }
            addr = luaL_checklstring(L,-1,&addr_len);
            if (addr_len != 16) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv6_addresses 'addr' value is not 16 bytes long");
            }
            memcpy(&v6_addr, addr, 16);

            lua_getfield(L, -1, "name");
            if (!lua_isstring(L,-1)) {
                lua_pop(L, 3); /* remove whatever it is, the key, and the ipv4_addreses table */
                return luaL_error(L, "CaptureInfo.host ipv6_addresses table's table does not contain an 'addr' field");
            }
            name = luaL_checklstring(L,-1,&name_len);

            wth->add_new_ipv6((const void *)(&v6_addr), name);

            /* removes 'value'; keeps 'key' for next iteration */
            lua_pop(L, 1);
        }
    }

    /* wasn't a table, or it was and we walked it; either way pop it */
    lua_pop(L,1);

    return 0;
}


/* WSLUA_ATTRIBUTE CaptureInfo_private_table RW A private Lua value unique to this file.

    The `private_table` is a field you set/get with your own Lua table.
    This is provided so that a Lua script can save per-file reading/writing
    state, because multiple files can be opened and read at the same time.

    For example, if the user issued a reload-file command, or Lua called the
    `reload()` function, then the current capture file is still open while a new one
    is being opened, and thus Wireshark will invoke `read_open()` while the previous
    capture file has not caused `read_close()` to be called; and if the `read_open()`
    succeeds then `read_close()` will be called right after that for the previous
    file, rather than the one just opened. Thus the Lua script can use this
    `private_table` to store a table of values specific to each file, by setting
    this `private_table` in the `read_open()` function, which it can then later get back
    inside its `read()`, `seek_read()`, and `read_close()` functions.
*/
static int CaptureInfo_get_private_table(lua_State* L) {
    CaptureInfo fi = checkCaptureInfo(L,1);
    return get_wth_priv_table_ref(L, fi->wth);
}

static int CaptureInfo_set_private_table(lua_State* L) {
    CaptureInfo fi = checkCaptureInfo(L,1);
    return set_wth_priv_table_ref(L, fi->wth);
}

WSLUA_ATTRIBUTES CaptureInfo_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,encap),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,time_precision),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,snapshot_length),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,comment),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,hardware),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,os),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,user_app),
    WSLUA_ATTRIBUTE_WOREG(CaptureInfo,hosts),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfo,private_table),
    { NULL, NULL, NULL }
};

WSLUA_META CaptureInfo_meta[] = {
    WSLUA_CLASS_MTREG(CaptureInfo,tostring),
    { NULL, NULL }
};

int CaptureInfo_register(lua_State* L) {
    WSLUA_REGISTER_META(CaptureInfo);
    WSLUA_REGISTER_ATTRIBUTES(CaptureInfo);
    return 0;
}


WSLUA_CLASS_DEFINE(CaptureInfoConst,FAIL_ON_NULL_MEMBER_OR_EXPIRED("CaptureInfoConst",wdh),NOP);
/*
    A `CaptureInfoConst` object, passed into Lua as an argument to the `FileHandler` callback
    function `write_open()`.

    This object represents capture file data and meta-data (data about the
    capture file) for the current capture in Wireshark/Tshark.

    This object's fields are read-from when used by `write_open` function callback.
    In other words, when the Lua plugin's FileHandler `write_open` function is invoked, a
    `CaptureInfoConst` object will be passed in as one of the arguments, and its fields
    should be read from by your Lua code to get data about the capture that needs to be written.

    @since 1.11.3
 */

static CaptureInfoConst* push_CaptureInfoConst(lua_State* L, wtap_dumper *wdh) {
    CaptureInfoConst f = (CaptureInfoConst) g_malloc0(sizeof(struct _wslua_captureinfo));
    f->wth = NULL;
    f->wdh = wdh;
    f->expired = FALSE;
    return pushCaptureInfoConst(L,f);
}

WSLUA_METAMETHOD CaptureInfoConst__tostring(lua_State* L) {
    /* Generates a string of debug info for the CaptureInfoConst */
    CaptureInfoConst fi = toCaptureInfoConst(L,1);

    if (!fi || !fi->wdh) {
        lua_pushstring(L,"CaptureInfoConst pointer is NULL!");
    } else {
        wtap_dumper *wdh = fi->wdh;
        lua_pushfstring(L, "CaptureInfoConst: file_type_subtype=%d, snaplen=%d, encap=%d, compressed=%d, tsprecision='%s'",
            wdh->file_type_subtype, wdh->snaplen, wdh->encap, wdh->compressed, wdh->tsprecision);
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

/* WSLUA_ATTRIBUTE CaptureInfoConst_type RO The file type. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfoConst,type,wdh->file_type_subtype);

/* WSLUA_ATTRIBUTE CaptureInfoConst_snapshot_length RO The maximum packet length that is actually recorded (vs. the original
    length of any given packet on-the-wire). A value of `0` means the snapshot length is unknown or there is no one
    such length for the whole file. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfoConst,snapshot_length,wdh->snaplen);

/* WSLUA_ATTRIBUTE CaptureInfoConst_encap RO The packet encapsulation type for the whole file.

    See `wtap_encaps` in init.lua for available types.  It is set to `wtap_encaps.PER_PACKET` if packets can
    have different types, in which case each Frame identifies its type, in `FrameInfo.packet_encap`. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfoConst,encap,wdh->encap);

/* WSLUA_ATTRIBUTE CaptureInfoConst_comment RW A comment for the whole capture file, if the
    `wtap_presence_flags.COMMENTS` was set in the presence flags; nil if there is no comment. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfoConst,comment,wth->shb_hdr.opt_comment);

/* WSLUA_ATTRIBUTE CaptureInfoConst_hardware RO A string containing the description of
    the hardware used to create the capture, or nil if there is no hardware string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfoConst,hardware,wth->shb_hdr.shb_hardware);

/* WSLUA_ATTRIBUTE CaptureInfoConst_os RO A string containing the name of
    the operating system used to create the capture, or nil if there is no os string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfoConst,os,wth->shb_hdr.shb_os);

/* WSLUA_ATTRIBUTE CaptureInfoConst_user_app RO A string containing the name of
    the application used to create the capture, or nil if there is no user_app string. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(CaptureInfoConst,user_app,wth->shb_hdr.shb_user_appl);

/* WSLUA_ATTRIBUTE CaptureInfoConst_hosts RO A ip-to-hostname Lua table of two key-ed names: `ipv4_addresses` and `ipv6_addresses`.
    The value of each of these names are themselves array tables, of key-ed tables, such that the inner table has a key
    `addr` set to the raw 4-byte or 16-byte IP address Lua string and a `name` set to the resolved name.

    For example, if the current capture has one resolved IPv4 address of 1.2.3.4 to `foo.com`, then getting
    `CaptureInfoConst.hosts` will get a table of:
    @code { ipv4_addresses = { { addr = "\01\02\03\04", name = "foo.com" } }, ipv6_addresses = { } } @endcode

    Note that either the `ipv4_addresses` or the `ipv6_addresses` table, or both, may be empty, however they will not
    be nil. */
static int CaptureInfoConst_get_hosts(lua_State* L) {
    CaptureInfoConst fi = checkCaptureInfoConst(L,1);
    wtap_dumper *wdh = fi->wdh;

    /* create the main table to return */
    lua_newtable(L);

    /* create the ipv4_addresses table */
    lua_newtable(L);

    if (wdh->addrinfo_lists && wdh->addrinfo_lists->ipv4_addr_list) {
        hashipv4_t *ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, 0);
        int i, j;
        for (i=1, j=1; ipv4_hash_list_entry != NULL; i++) {
            if ((ipv4_hash_list_entry->flags & USED_AND_RESOLVED_MASK) == RESOLVED_ADDRESS_USED) {
                lua_pushnumber(L, j); /* push numeric index key starting at 1, so it will be an array table */
                /* create the entry table */
                lua_newtable(L);
                /* addr is in network order already */
                lua_pushlstring(L, (char*)(&ipv4_hash_list_entry->ip), 4);
                lua_setfield(L, -2, "addr");
                lua_pushstring(L, ipv4_hash_list_entry->name);
                lua_setfield(L, -2, "name");
                /* now our ipv4_addresses table is at -3, key number is -2, and entry table at -2, so we're good */
                lua_settable(L, -3);
                j++;
            }
            ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
        }
    }

    /* set the (possibly empty) ipv4_addresses table into the main table */
    lua_setfield(L, -2, "ipv4_addresses");

    /* create the ipv6_addresses table */
    lua_newtable(L);

    if (wdh->addrinfo_lists && wdh->addrinfo_lists->ipv6_addr_list) {
        hashipv6_t *ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, 0);
        int i, j;
        for (i=1, j=1; ipv6_hash_list_entry != NULL; i++) {
            if ((ipv6_hash_list_entry->flags & USED_AND_RESOLVED_MASK) == RESOLVED_ADDRESS_USED) {
                lua_pushnumber(L, j); /* push numeric index key starting at 1, so it will be an array table */
                /* create the entry table */
                lua_newtable(L);
                /* addr is in network order already */
                lua_pushlstring(L, (char*)(&ipv6_hash_list_entry->addr.bytes[0]), 16);
                lua_setfield(L, -2, "addr");
                lua_pushstring(L, ipv6_hash_list_entry->name);
                lua_setfield(L, -2, "name");
                /* now our ipv6_addresses table is at -3, key number is -2, and entry table at -2, so we're good */
                lua_settable(L, -3);
                j++;
            }
            ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
        }
    }

    /* set the (possibly empty) ipv6_addresses table into the main table */
    lua_setfield(L, -2, "ip6_addresses");

    /* return the main table */
    return 1;
}

/* WSLUA_ATTRIBUTE CaptureInfoConst_private_table RW A private Lua value unique to this file.

    The `private_table` is a field you set/get with your own Lua table.
    This is provided so that a Lua script can save per-file reading/writing
    state, because multiple files can be opened and read at the same time.

    For example, if two Lua scripts issue a `Dumper:new_for_current()` call and the
    current file happens to use your script's writer, then the Wireshark will invoke
    `write_open()` while the previous capture file has not had `write_close()` called.
    Thus the Lua script can use this `private_table` to store a table of values
    specific to each file, by setting this `private_table` in the write_open()
    function, which it can then later get back inside its `write()`, and `write_close()`
    functions.
*/
static int CaptureInfoConst_get_private_table(lua_State* L) {
    CaptureInfoConst fi = checkCaptureInfoConst(L,1);
    return get_wdh_priv_table_ref(L, fi->wdh);
}

static int CaptureInfoConst_set_private_table(lua_State* L) {
    CaptureInfoConst fi = checkCaptureInfoConst(L,1);
    return set_wdh_priv_table_ref(L, fi->wdh);
}

static int CaptureInfoConst__gc(lua_State* L _U_) {
    CaptureInfoConst fi = toCaptureInfoConst(L,1);
    if (fi)
        g_free(fi);
    return 0;
}

WSLUA_ATTRIBUTES CaptureInfoConst_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,encap),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,type),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,snapshot_length),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,comment),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,hardware),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,os),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,user_app),
    WSLUA_ATTRIBUTE_ROREG(CaptureInfoConst,hosts),
    WSLUA_ATTRIBUTE_RWREG(CaptureInfoConst,private_table),
    { NULL, NULL, NULL }
};

WSLUA_META CaptureInfoConst_meta[] = {
    WSLUA_CLASS_MTREG(CaptureInfoConst,tostring),
    { NULL, NULL }
};

int CaptureInfoConst_register(lua_State* L) {
    WSLUA_REGISTER_META(CaptureInfoConst);
    WSLUA_REGISTER_ATTRIBUTES(CaptureInfoConst);
    return 0;
}


WSLUA_CLASS_DEFINE(FrameInfo,FAIL_ON_NULL_OR_EXPIRED("FrameInfo"),NOP);
/*
    A FrameInfo object, passed into Lua as an argument by FileHandler callback
    functions (e.g., `read`, `seek_read`, etc.).

    This object represents frame data and meta-data (data about the frame/packet)
    for a given `read`/`seek_read`/`write`'s frame.

    This object's fields are written-to/set when used by read function callbacks, and
    read-from/get when used by file write function callbacks.  In other words, when
    the Lua plugin's FileHandler `read`/`seek_read`/etc. functions are invoked, a
    FrameInfo object will be passed in as one of the arguments, and its fields
    should be written-to/set based on the frame information read from the file;
    whereas when the Lua plugin's `FileHandler.write()` function is invoked, the
    `FrameInfo` object passed in should have its fields read-from/get, to write that
    frame information to the file.

    @since 1.11.3
 */

static FrameInfo* push_FrameInfo(lua_State* L, struct wtap_pkthdr *phdr, Buffer* buf) {
    FrameInfo f = (FrameInfo) g_malloc0(sizeof(struct _wslua_phdr));
    f->phdr = phdr;
    f->buf = buf;
    f->expired = FALSE;
    return pushFrameInfo(L,f);
}

WSLUA_METAMETHOD FrameInfo__tostring(lua_State* L) {
    /* Generates a string of debug info for the FrameInfo */
    FrameInfo fi = toFrameInfo(L,1);

    if (!fi) {
        lua_pushstring(L,"FrameInfo pointer is NULL!");
    } else {
        if (fi->phdr)
            lua_pushfstring(L, "FrameInfo: rec_type=%u, presence_flags=%d, caplen=%d, len=%d, pkt_encap=%d, opt_comment='%s'",
                fi->phdr->rec_type, fi->phdr->presence_flags, fi->phdr->caplen, fi->phdr->len, fi->phdr->pkt_encap, fi->phdr->opt_comment);
        else
            lua_pushstring(L, "FrameInfo phdr pointer is NULL!");
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

/* XXX: should this function be a method of File instead? */
WSLUA_METHOD FrameInfo_read_data(lua_State* L) {
    /* Tells Wireshark to read directly from given file into frame data buffer, for length bytes. Returns true if succeeded, else false. */
#define WSLUA_ARG_FrameInfo_read_data_FILE 2 /* The File object userdata, provided by Wireshark previously in a reading-based callback. */
#define WSLUA_ARG_FrameInfo_read_data_LENGTH 3 /* The number of bytes to read from the file at the current cursor position. */
    FrameInfo fi = checkFrameInfo(L,1);
    File fh = checkFile(L,WSLUA_ARG_FrameInfo_read_data_FILE);
    guint32 len = wslua_checkguint32(L, WSLUA_ARG_FrameInfo_read_data_LENGTH);
    int err = 0;
    gchar *err_info = NULL;

    if (!fi->buf || !fh->file) {
        luaL_error(L, "FrameInfo read_data() got null buffer or file pointer internally");
        return 0;
    }

    if (!wtap_read_packet_bytes(fh->file, fi->buf, len, &err, &err_info)) {
        lua_pushboolean(L, FALSE);
        if (err_info) {
            lua_pushstring(L, err_info);
            g_free(err_info); /* is this right? */
        }
        else lua_pushnil(L);
        lua_pushnumber(L, err);
        return 3;
    }

    lua_pushboolean(L, TRUE);

    WSLUA_RETURN(1); /* True if succeeded, else returns false along with the error number and string error description. */
}

/* free the struct we created, but not the phdr/buf it points to */
static int FrameInfo__gc(lua_State* L _U_) {
    FrameInfo fi = toFrameInfo(L,1);
    if (fi)
        g_free(fi);
    return 0;
}

/* WSLUA_ATTRIBUTE FrameInfo_time RW The packet timestamp as an NSTime object.

    Note: Set the `FileHandler.time_precision` to the appropriate `wtap_file_tsprec` value as well.
 */
static int FrameInfo_set_time (lua_State* L) {
    FrameInfo fi = checkFrameInfo(L,1);
    NSTime nstime = checkNSTime(L,2);

    if (!fi->phdr) return 0;

    fi->phdr->ts.secs  = nstime->secs;
    fi->phdr->ts.nsecs = nstime->nsecs;

    return 0;
}

static int FrameInfo_get_time (lua_State* L) {
    FrameInfo fi = checkFrameInfo(L,1);
    NSTime nstime = (NSTime)g_malloc(sizeof(nstime_t));

    if (!nstime) return 0;

    nstime->secs  = fi->phdr->ts.secs;
    nstime->nsecs = fi->phdr->ts.nsecs;

    pushNSTime(L,nstime);

    return 1; /* An NSTime object of the frame's timestamp. */
}

/* WSLUA_ATTRIBUTE FrameInfo_data RW The data buffer containing the packet.

   @note This cannot be cleared once set.
 */
static int FrameInfo_set_data (lua_State* L) {
    FrameInfo fi = checkFrameInfo(L,1);

    if (!fi->phdr) {
        g_warning("Error in FrameInfo set data: NULL pointer");
        return 0;
    }

    if (!fi->buf) {
        g_warning("Error in FrameInfo set data: NULL frame_buffer pointer");
        return 0;
    }

   if (lua_isstring(L,2)) {
        size_t len = 0;
        const gchar* s = luaL_checklstring(L,2,&len);
        if (s) {
            /* Make sure we have enough room for the packet */
            buffer_assure_space(fi->buf, len);
            memcpy(buffer_start_ptr(fi->buf), s, len);
            fi->phdr->caplen = (guint32) len;
            fi->phdr->len = (guint32) len;
        } else {
            luaL_error(L, "FrameInfo's attribute 'data' did not get a valid Lua string");
        }
    }
    else
        luaL_error(L, "FrameInfo's attribute 'data' must be a Lua string");

    return 0;
}

static int FrameInfo_get_data (lua_State* L) {
    FrameInfo fi = checkFrameInfo(L,1);

    if (!fi->buf) return 0;

    lua_pushlstring(L, buffer_start_ptr(fi->buf), buffer_length(fi->buf));

    WSLUA_RETURN(1); /* A Lua string of the frame buffer's data. */
}

/* WSLUA_ATTRIBUTE FrameInfo_rec_type RW The record type of the packet frame

    See `wtap_rec_types` in `init.lua` for values. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfo,rec_type,phdr->rec_type);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FrameInfo,rec_type,phdr->rec_type,guint);

/* WSLUA_ATTRIBUTE FrameInfo_flags RW The presence flags of the packet frame.

    See `wtap_presence_flags` in `init.lua` for bit values. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfo,flags,phdr->presence_flags);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FrameInfo,flags,phdr->presence_flags,guint32);

/* WSLUA_ATTRIBUTE FrameInfo_captured_length RW The captured packet length,
    and thus the length of the buffer passed to the `FrameInfo.data` field. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfo,captured_length,phdr->caplen);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FrameInfo,captured_length,phdr->caplen,guint32);

/* WSLUA_ATTRIBUTE FrameInfo_original_length RW The on-the-wire packet length,
    which may be longer than the `captured_length`. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfo,original_length,phdr->len);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FrameInfo,original_length,phdr->len,guint32);

/* WSLUA_ATTRIBUTE FrameInfo_encap RW The packet encapsulation type for the frame/packet,
    if the file supports per-packet types. See `wtap_encaps` in `init.lua` for possible
    packet encapsulation types to use as the value for this field. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfo,encap,phdr->pkt_encap);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FrameInfo,encap,phdr->pkt_encap,int);

/* WSLUA_ATTRIBUTE FrameInfo_comment RW A string comment for the packet, if the
    `wtap_presence_flags.COMMENTS` was set in the presence flags; nil if there is no comment. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(FrameInfo,comment,phdr->opt_comment);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(FrameInfo,comment,phdr->opt_comment,TRUE);

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES FrameInfo_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,rec_type),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,flags),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,captured_length),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,original_length),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,comment),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,encap),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,time),
    WSLUA_ATTRIBUTE_RWREG(FrameInfo,data),
    { NULL, NULL, NULL }
};

WSLUA_METHODS FrameInfo_methods[] = {
    WSLUA_CLASS_FNREG(FrameInfo,read_data),
    { NULL, NULL }
};

WSLUA_META FrameInfo_meta[] = {
    WSLUA_CLASS_MTREG(FrameInfo,tostring),
    { NULL, NULL }
};

int FrameInfo_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(FrameInfo);
    WSLUA_REGISTER_ATTRIBUTES(FrameInfo);
    return 0;
}

WSLUA_CLASS_DEFINE(FrameInfoConst,FAIL_ON_NULL_OR_EXPIRED("FrameInfo"),NOP);
/*
    A constant FrameInfo object, passed into Lua as an argument by the FileHandler write
    callback function.  This has similar attributes/properties as FrameInfo, but the fields can
    only be read from, not written to.

    @since 1.11.3
 */

static FrameInfoConst* push_FrameInfoConst(lua_State* L, const struct wtap_pkthdr *phdr, const guint8 *pd) {
    FrameInfoConst f = (FrameInfoConst) g_malloc(sizeof(struct _wslua_const_phdr));
    f->phdr = phdr;
    f->pd = pd;
    f->expired = FALSE;
    return pushFrameInfoConst(L,f);
}

WSLUA_METAMETHOD FrameInfoConst__tostring(lua_State* L) {
    /* Generates a string of debug info for the FrameInfo */
    FrameInfoConst fi = toFrameInfoConst(L,1);

    if (!fi) {
        lua_pushstring(L,"FrameInfo pointer is NULL!");
    } else {
        if (fi->phdr && !fi->expired)
            lua_pushfstring(L, "FrameInfo: rec_type=%u, presence_flags=%d, caplen=%d, len=%d, pkt_encap=%d, opt_comment='%s'",
                fi->phdr->rec_type, fi->phdr->presence_flags, fi->phdr->caplen, fi->phdr->len, fi->phdr->pkt_encap, fi->phdr->opt_comment);
        else
            lua_pushfstring(L, "FrameInfo has %s", fi->phdr?"expired":"null phdr pointer");
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

/* XXX: should this function be a method of File instead? */
WSLUA_METHOD FrameInfoConst_write_data(lua_State* L) {
    /* Tells Wireshark to write directly to given file from the frame data buffer, for length bytes. Returns true if succeeded, else false. */
#define WSLUA_ARG_FrameInfoConst_write_data_FILE 2 /* The File object userdata, provided by Wireshark previously in a writing-based callback. */
#define WSLUA_OPTARG_FrameInfoConst_write_data_LENGTH 3 /* The number of bytes to write to the file at the current cursor position, or all if not supplied. */
    FrameInfoConst fi = checkFrameInfoConst(L,1);
    File fh = checkFile(L,WSLUA_ARG_FrameInfoConst_write_data_FILE);
    guint32 len = wslua_optguint32(L, WSLUA_OPTARG_FrameInfoConst_write_data_LENGTH, fi->phdr ? fi->phdr->caplen:0);
    int err = 0;

    if (!fi->pd || !fi->phdr || !fh->wdh) {
        luaL_error(L, "FrameInfoConst write_data() got null buffer or file pointer internally");
        return 0;
    }

    if (len > fi->phdr->caplen)
        len = fi->phdr->caplen;

    if (!wtap_dump_file_write(fh->wdh, fi->pd, (size_t)(len), &err)) {
        lua_pushboolean(L, FALSE);
        lua_pushfstring(L, "FrameInfoConst write_data() error: %s", g_strerror(err));
        lua_pushnumber(L, err);
        return 3;
    }

    lua_pushboolean(L, TRUE);

    WSLUA_RETURN(1); /* True if succeeded, else returns false along with the error number and string error description. */
}

/* free the struct we created, but not the wtap_pkthdr it points to */
static int FrameInfoConst__gc(lua_State* L _U_) {
    FrameInfoConst fi = toFrameInfoConst(L,1);
    if (fi)
        g_free(fi);
    return 0;
}

/* WSLUA_ATTRIBUTE FrameInfoConst_time RO The packet timestamp as an NSTime object. */
static int FrameInfoConst_get_time (lua_State* L) {
    FrameInfoConst fi = checkFrameInfoConst(L,1);
    NSTime nstime = (NSTime)g_malloc(sizeof(nstime_t));

    if (!nstime) return 0;

    nstime->secs  = fi->phdr->ts.secs;
    nstime->nsecs = fi->phdr->ts.nsecs;

    pushNSTime(L,nstime);

    return 1; /* An NSTime object of the frame's timestamp. */
}

/* WSLUA_ATTRIBUTE FrameInfoConst_data RO The data buffer containing the packet.  */
static int FrameInfoConst_get_data (lua_State* L) {
    FrameInfoConst fi = checkFrameInfoConst(L,1);

    if (!fi->pd || !fi->phdr) return 0;

    lua_pushlstring(L, fi->pd, fi->phdr->caplen);

    return 1;
}

/* WSLUA_ATTRIBUTE FrameInfoConst_rec_type RO The record type of the packet frame - see `wtap_presence_flags` in `init.lua` for values. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfoConst,rec_type,phdr->rec_type);

/* WSLUA_ATTRIBUTE FrameInfoConst_flags RO The presence flags of the packet frame - see `wtap_presence_flags` in `init.lua` for bits. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfoConst,flags,phdr->presence_flags);

/* WSLUA_ATTRIBUTE FrameInfoConst_captured_length RO The captured packet length, and thus the length of the buffer in the FrameInfoConst.data field. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfoConst,captured_length,phdr->caplen);

/* WSLUA_ATTRIBUTE FrameInfoConst_original_length RO The on-the-wire packet length, which may be longer than the `captured_length`. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfoConst,original_length,phdr->len);

/* WSLUA_ATTRIBUTE FrameInfoConst_encap RO The packet encapsulation type, if the file supports per-packet types.

      See `wtap_encaps` in `init.lua` for possible packet encapsulation types to use as the value for this field. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FrameInfoConst,encap,phdr->pkt_encap);

/* WSLUA_ATTRIBUTE FrameInfoConst_comment RO A comment for the packet; nil if there is none. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(FrameInfoConst,comment,phdr->opt_comment);

WSLUA_ATTRIBUTES FrameInfoConst_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,rec_type),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,flags),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,captured_length),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,original_length),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,encap),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,comment),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,time),
    WSLUA_ATTRIBUTE_ROREG(FrameInfoConst,data),
    { NULL, NULL, NULL }
};

WSLUA_METHODS FrameInfoConst_methods[] = {
    WSLUA_CLASS_FNREG(FrameInfoConst,write_data),
    { NULL, NULL }
};

WSLUA_META FrameInfoConst_meta[] = {
    WSLUA_CLASS_MTREG(FrameInfoConst,tostring),
    { NULL, NULL }
};

int FrameInfoConst_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(FrameInfoConst);
    WSLUA_REGISTER_ATTRIBUTES(FrameInfoConst);
    return 0;
}


WSLUA_CLASS_DEFINE(FileHandler,NOP,NOP);
/*
    A FileHandler object, created by a call to FileHandler.new(arg1, arg2, ...).
    The FileHandler object lets you create a file-format reader, or writer, or
    both, by setting your own read_open/read or write_open/write functions.

    @since 1.11.3
 */

static int filehandler_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    const gchar* functype = luaL_optstring(L, lua_upvalueindex(1), "UNKNOWN");
    report_failure("Lua: Error During execution of FileHandler %s callback:\n %s",functype,error);
    lua_pop(L, 1);
    return 0;
}

static int push_error_handler(lua_State* L, const gchar* funcname) {
    lua_pushstring(L, funcname);
    lua_pushcclosure(L, filehandler_cb_error_handler, 1);
    return 1;
}


/* During file routines, we cannot allow the FileHandler to get de-registered, since
   that would change the GArray's in file_access.c and hilarity would ensue. So we
   set this to true right before pcall(), and back to false afterwards */
static gboolean in_routine = FALSE;

/* This does the verification and setup common to all open/read/seek_read/close routines */
#define INIT_FILEHANDLER_ROUTINE(name,retval) \
    if (!fh) { \
        g_warning("Error in file %s: no Lua FileHandler object", #name); \
        return retval; \
    } \
    if (!fh->registered) { \
        g_warning("Error in file %s: Lua FileHandler is not registered", #name); \
        return retval; \
    } \
    if (!fh->L) { \
        g_warning("Error in file %s: no FileHandler Lua state", #name); \
        return retval; \
    } \
    if (fh->name##_ref == LUA_NOREF) { \
        g_warning("Error in file %s: no FileHandler %s routine reference", #name, #name); \
        return retval; \
    } \
    L = fh->L; \
    lua_settop(L,0); \
    push_error_handler(L, #name " routine"); \
    lua_rawgeti(L, LUA_REGISTRYINDEX, fh->name##_ref); \
    if (!lua_isfunction(L, -1)) { \
         g_warning("Error in file %s: no FileHandler %s routine function in Lua", #name, #name); \
        return retval; \
    } \
    /* now guard against de-registering during pcall() */ \
    in_routine = TRUE;

#define END_FILEHANDLER_ROUTINE() \
    /* now allow de-registering again */ \
    in_routine = TRUE;


/* LUA_ERRGCMM is in Lua 5.2 only - making it 9 disables it */
#ifndef LUA_ERRGCMM
#define LUA_ERRGCMM 9
#endif

#define CASE_ERROR(name) \
    case LUA_ERRRUN: \
        g_warning("Run-time error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRMEM: \
        g_warning("Memory alloc error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRERR: \
        g_warning("Error in error handling while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRGCMM: \
        g_warning("Error in garbage collector while calling FileHandler %s routine", name); \
        break; \
    default: \
        g_assert_not_reached(); \
        break;

#define CASE_ERROR_ERRINFO(name) \
    case LUA_ERRRUN: \
        g_warning("Run-time error while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Run-time error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRMEM: \
        g_warning("Memory alloc error while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Memory alloc error while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRERR: \
        g_warning("Error in error handling while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Error in error handling while calling FileHandler %s routine", name); \
        break; \
    case LUA_ERRGCMM: \
        g_warning("Error in garbage collector while calling FileHandler %s routine", name); \
        *err_info = g_strdup_printf("Error in garbage collector while calling FileHandler %s routine", name); \
        break; \
    default: \
        g_assert_not_reached(); \
        break;


/* some declarations */
static gboolean
wslua_filehandler_read(wtap *wth, int *err, gchar **err_info,
                      gint64 *data_offset);
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info);
static void
wslua_filehandler_close(wtap *wth);
static void
wslua_filehandler_sequential_close(wtap *wth);


/* This is our one-and-only open routine for file handling.  When called by
 * file_access.c, the wtap wth argument has a void* wslua_data that holds the specific
 * FileHandler for the specific registered file format reader.  It has this because
 * we passed it in when we registered the open routine.
 * The open_file_* routines should return:
 *  -1 on an I/O error;
 *  1 if the file they're reading is one of the types it handles;
 *  0 if the file they're reading isn't the type they're checking for.
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct wtap" to the type of the file.
 */
static int
wslua_filehandler_open(wtap *wth, int *err _U_, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = 0;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(read_open,0);

    create_wth_priv(L, wth);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, TRUE);

    errno = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("read_open")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    if (retval == 1) {
        /* this is our file type - set the routines and settings into wtap */

        if (fh->read_ref != LUA_NOREF) {
            wth->subtype_read = wslua_filehandler_read;
        }
        else return 0;

        if (fh->seek_read_ref != LUA_NOREF) {
            wth->subtype_seek_read = wslua_filehandler_seek_read;
        }
        else return 0;

        /* it's ok to not have a close routine */
        if (fh->read_close_ref != LUA_NOREF)
            wth->subtype_close = wslua_filehandler_close;
        else
            wth->subtype_close = NULL;

        /* it's ok to not have a sequential close routine */
        if (fh->seq_read_close_ref != LUA_NOREF)
            wth->subtype_sequential_close = wslua_filehandler_sequential_close;
        else
            wth->subtype_sequential_close = NULL;

        wth->file_type_subtype = fh->file_type;
    }
    else {
        /* not our file type */
        remove_wth_priv(L, wth);
    }

    lua_settop(L,0);
    return retval;
}

/* The classic wtap read routine.  This returns TRUE if it found the next packet,
 * else FALSE.
 * If it finds a frame/packet, it should set the pseudo-header info (ie, let Lua set it).
 * Also Lua needs to set data_offset to the beginning of the line we're returning.
 * This will be the seek_off parameter when this frame is re-read.
*/
static gboolean
wslua_filehandler_read(wtap *wth, int *err, gchar **err_info,
                      gint64 *data_offset)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(read,FALSE);

    /* Reset errno */
    *err = errno = 0;

    wth->phdr.opt_comment = NULL;

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, &wth->phdr, wth->frame_buffer);

    errno = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            if (lua_isnumber(L,-1)) {
                *data_offset = wslua_togint64(L, -1);
                retval = 1;
                break;
            }
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("read")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
}

/* Classic wtap seek_read function, called by wtap core.  This must return TRUE on
 * success, FALSE on error.
 */
static gboolean
wslua_filehandler_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;
    FrameInfo *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(seek_read,FALSE);

    /* Reset errno */
    *err = errno = 0;
    phdr->opt_comment = NULL;

    fp = push_File(L, wth->random_fh);
    fc = push_CaptureInfo(L, wth, FALSE);
    fi = push_FrameInfo(L, phdr, buf);
    lua_pushnumber(L, (lua_Number)seek_off);

    *err = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,4,1,1) ) {
        case 0:
            if (lua_isstring(L,-1)) {
                size_t len = 0;
                const gchar* fd = lua_tolstring(L, -1, &len);
                if (len < WTAP_MAX_PACKET_SIZE)
                    memcpy(buffer_start_ptr(buf), fd, len);
                retval = 1;
                break;
            }
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR_ERRINFO("seek_read")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;
    lua_settop(L,0);

    return (retval == 1);
}

/* Classic wtap close function, called by wtap core.
 */
static void
wslua_filehandler_close(wtap *wth)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(read_close,);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("read_close")
    }

    END_FILEHANDLER_ROUTINE();

    remove_wth_priv(L, wth);

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    lua_settop(L,0);

    return;
}

/* Classic wtap sequential close function, called by wtap core.
 */
static void
wslua_filehandler_sequential_close(wtap *wth)
{
    FileHandler fh = (FileHandler)(wth->wslua_data);
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfo *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(seq_read_close,);

    fp = push_File(L, wth->fh);
    fc = push_CaptureInfo(L, wth, FALSE);

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            break;
        CASE_ERROR("seq_read_close")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    lua_settop(L,0);

    return;
}


/* basically a dummy function to use for can_write_encap so that the caller calls
 * wslua_can_write_encap instead (which will be wslua_filehandler_can_write_encap)
 */
static int
wslua_dummy_can_write_encap(int encap _U_)
{
    return WTAP_ERR_CHECK_WSLUA;
}

/* Similar to the classic wtap can_write_encap function.
 * This returns 0 if the encap is ok for this file type.
 */
static int
wslua_filehandler_can_write_encap(int encap, void* data)
{
    FileHandler fh = (FileHandler)(data);
    int retval = WTAP_ERR_UNSUPPORTED_ENCAP;
    lua_State* L = NULL;

    INIT_FILEHANDLER_ROUTINE(can_write_encap,WTAP_ERR_INTERNAL);

    lua_pushnumber(L, encap);

    errno = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,1,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,WTAP_ERR_UNSUPPORTED_ENCAP);
            break;
        CASE_ERROR("can_write_encap")
    }

    END_FILEHANDLER_ROUTINE();

    /* the retval we got was either a 1 for true, 0 for false, or WTAP_ERR_UNSUPPORTED_ENCAP;
       but can_write_encap() expects 0 to be true/yes */
    if (retval == 1) {
        retval = 0;
    } else if (retval == 0) {
        retval = WTAP_ERR_UNSUPPORTED_ENCAP;
    }

    return retval;
}

/* some declarations */
static gboolean
wslua_filehandler_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                      const guint8 *pd, int *err);
static gboolean
wslua_filehandler_dump_close(wtap_dumper *wdh, int *err);


/* The classic wtap dump_open function.
 * This returns 1 (TRUE) on success.
 */
static int
wslua_filehandler_dump_open(wtap_dumper *wdh, int *err)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = 0;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_open,0);

    create_wdh_priv(L, wdh);

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);

    /* Reset err */
    *err = 0;

    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write_open")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    if (retval == 1) {
        /* this is our file type - set the routines and settings into wtap */

        if (fh->write_ref != LUA_NOREF) {
            wdh->subtype_write = wslua_filehandler_dump;
        }
        else {
            g_warning("FileHandler was not set with a write function, even though write_open() returned true");
            return 0;
        }

        /* it's ok to not have a close routine */
        if (fh->write_close_ref != LUA_NOREF)
            wdh->subtype_close = wslua_filehandler_dump_close;
        else
            wdh->subtype_close = NULL;
    }
    else {
        /* not our file type? */
        remove_wdh_priv(L, wdh);
    }

    return retval;
}

/* The classic wtap dump routine.  This returns TRUE if it writes the current packet,
 * else FALSE.
*/
static gboolean
wslua_filehandler_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                      const guint8 *pd, int *err)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;
    FrameInfoConst *fi = NULL;

    INIT_FILEHANDLER_ROUTINE(write,FALSE);

    /* Reset errno */
    *err = errno = 0;

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);
    fi = push_FrameInfoConst(L, phdr, pd);

    errno = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,3,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write")
    }

    END_FILEHANDLER_ROUTINE();

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;
    (*fi)->expired = TRUE;

    return (retval == 1);
}

/* The classic wtap dump_close routine.  This returns TRUE if it closes cleanly,
 * else FALSE.
*/
static gboolean
wslua_filehandler_dump_close(wtap_dumper *wdh, int *err)
{
    FileHandler fh = (FileHandler)(wdh->wslua_data);
    int retval = -1;
    lua_State* L = NULL;
    File *fp = NULL;
    CaptureInfoConst *fc = NULL;

    INIT_FILEHANDLER_ROUTINE(write_close,FALSE);

    /* Reset errno */
    *err = errno = 0;

    fp = push_Wdh(L, wdh);
    fc = push_CaptureInfoConst(L,wdh);

    errno = WTAP_ERR_CANT_READ;
    switch ( lua_pcall(L,2,1,1) ) {
        case 0:
            retval = wslua_optboolint(L,-1,0);
            break;
        CASE_ERROR("write_close")
    }

    END_FILEHANDLER_ROUTINE();

    remove_wdh_priv(L, wdh);

    (*fp)->expired = TRUE;
    (*fc)->expired = TRUE;

    return (retval == 1);
}


WSLUA_CONSTRUCTOR FileHandler_new(lua_State* L) {
    /* Creates a new FileHandler */
#define WSLUA_ARG_FileHandler_new_NAME 1 /* The name of the file type, for display purposes only. E.g., "Wireshark - pcapng" */
#define WSLUA_ARG_FileHandler_new_SHORTNAME 2 /* the file type short name, used as a shortcut in various places. E.g., "pcapng". Note: the name cannot already be in use. */
#define WSLUA_ARG_FileHandler_new_DESCRIPTION 3 /* Descriptive text about this file format, for display purposes only */
#define WSLUA_ARG_FileHandler_new_TYPE 4 /* The type of FileHandler, "r"/"w"/"rw" for reader/writer/both, include "m" for magic, "s" for strong heuristic */

    const gchar* name = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_NAME);
    const gchar* short_name = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_SHORTNAME);
    const gchar* desc = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_DESCRIPTION);
    const gchar* type = luaL_checkstring(L,WSLUA_ARG_FileHandler_new_TYPE);
    FileHandler fh = (FileHandler) g_malloc0(sizeof(struct _wslua_filehandler));

    fh->is_reader = (strchr(type,'r') != NULL) ? TRUE : FALSE;
    fh->is_writer = (strchr(type,'w') != NULL) ? TRUE : FALSE;

    if (fh->is_reader && wtap_has_open_info(short_name)) {
        return luaL_error(L, "FileHandler.new: '%s' short name already exists for a reader!", short_name);
    }

    if (fh->is_writer && wtap_short_string_to_file_type_subtype(short_name) > -1) {
        return luaL_error(L, "FileHandler.new: '%s' short name already exists for a writer!", short_name);
    }

    fh->type = g_strdup(type);
    fh->finfo.name = g_strdup(name);
    fh->finfo.short_name = g_strdup(short_name);
    fh->finfo.default_file_extension = NULL;
    fh->finfo.additional_file_extensions = NULL;
    fh->finfo.writing_must_seek = FALSE;
    fh->finfo.has_name_resolution = FALSE;
    fh->finfo.can_write_encap = NULL;
    fh->finfo.dump_open = NULL;
    /* this will be set to a new file_type when registered */
    fh->file_type = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;

    fh->description = g_strdup(desc);
    fh->L = L;
    fh->read_open_ref = LUA_NOREF;
    fh->read_ref = LUA_NOREF;
    fh->seek_read_ref = LUA_NOREF;
    fh->read_close_ref = LUA_NOREF;
    fh->seq_read_close_ref = LUA_NOREF;
    fh->write_open_ref = LUA_NOREF;
    fh->write_ref = LUA_NOREF;
    fh->write_close_ref = LUA_NOREF;
    fh->can_write_encap_ref = LUA_NOREF;

    fh->registered = FALSE;

    pushFileHandler(L,fh);
    WSLUA_RETURN(1); /* The newly created FileHandler object */
}

WSLUA_METAMETHOD FileHandler__tostring(lua_State* L) {
    /* Generates a string of debug info for the FileHandler */
    FileHandler fh = toFileHandler(L,1);

    if (!fh) {
        lua_pushstring(L,"FileHandler pointer is NULL!");
    } else {
        lua_pushfstring(L, "FileHandler(%s): short-name='%s', description='%s', read_open=%d, read=%d, write=%d",
            fh->finfo.name, fh->finfo.short_name, fh->description, fh->read_open_ref, fh->read_ref, fh->write_ref);
    }

    WSLUA_RETURN(1); /* String of debug information. */
}

static int FileHandler__gc(lua_State* L _U_) {
    /* do NOT free FileHandler, it's never free'd */
    /* TODO: handle this and other Lua things that should be free'd on exit, in a better way */
    return 0;
}

/* A Lua File handler must not be expired, and must be either a reader or writer, and
 * a *reader* one MUST at least define read_open, read, and seek_read funcs; and
 * a *writer* one MUST at least define can_write_encap, write_open, and write funcs
 */
static gboolean verify_filehandler_complete(FileHandler fh) {
    return ((fh->is_reader || fh->is_writer) &&
            (!fh->is_reader ||
             (fh->is_reader &&
              fh->read_open_ref != LUA_NOREF &&
              fh->read_ref      != LUA_NOREF &&
              fh->seek_read_ref != LUA_NOREF)) &&
            (!fh->is_writer ||
             (fh->is_writer &&
              fh->can_write_encap_ref != LUA_NOREF &&
              fh->write_open_ref      != LUA_NOREF &&
              fh->write_ref           != LUA_NOREF)) );
}


WSLUA_FUNCTION wslua_register_filehandler(lua_State* L) {
    /* Register the FileHandler into Wireshark/tshark, so they can read/write this new format.
       All functions and settings must be complete before calling this registration function.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_register_filehandler_FILEHANDLER 1 /* the FileHandler object to be registered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_register_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"a FileHAndler cannot be registered during reading/writing callback functions");

    if (fh->registered)
        return luaL_error(L,"this FileHandler is already registered");

    if (!verify_filehandler_complete(fh))
        return luaL_error(L,"this FileHandler is not complete enough to register");

    if (fh->is_writer) {
        fh->finfo.can_write_encap = wslua_dummy_can_write_encap;
        fh->finfo.wslua_info = (wtap_wslua_file_info_t*) g_malloc0(sizeof(wtap_wslua_file_info_t));
        fh->finfo.wslua_info->wslua_can_write_encap = wslua_filehandler_can_write_encap;
        fh->finfo.wslua_info->wslua_data = (void*)(fh);
        fh->finfo.dump_open = wslua_filehandler_dump_open;
    }

    fh->file_type = wtap_register_file_type_subtypes(&(fh->finfo),fh->file_type);

    if (fh->is_reader) {
        struct open_info oi = { NULL, OPEN_INFO_HEURISTIC, NULL, NULL, NULL, NULL };
        oi.name = fh->finfo.short_name;
        oi.open_routine = wslua_filehandler_open;
        oi.extensions = fh->finfo.additional_file_extensions;
        oi.wslua_data = (void*)(fh);
        if (strchr(fh->type,'m') != NULL) {
            oi.type = OPEN_INFO_MAGIC;
        } else {
            oi.type = OPEN_INFO_HEURISTIC;
        }
        wtap_register_open_info(&oi, (strchr(fh->type,'s') != NULL));
    }

    fh->registered = TRUE;

    lua_pushnumber(L, fh->file_type);

    WSLUA_RETURN(1); /* the new type number for this file reader/write */
}

WSLUA_FUNCTION wslua_deregister_filehandler(lua_State* L) {
    /* De-register the FileHandler from Wireshark/tshark, so it no longer gets used for reading/writing/display.
       This function cannot be called inside the reading/writing callback functions. */
#define WSLUA_ARG_register_filehandler_FILEHANDLER 1 /* the FileHandler object to be de-registered */
    FileHandler fh = checkFileHandler(L,WSLUA_ARG_register_filehandler_FILEHANDLER);

    if (in_routine)
        return luaL_error(L,"A FileHAndler cannot be de-registered during reading/writing callback functions");

    if (!fh->registered)
        return 0;

    /* undo writing stuff, even if it wasn't a writer */
    fh->finfo.can_write_encap = NULL;
    if (fh->finfo.wslua_info) {
        fh->finfo.wslua_info->wslua_can_write_encap = NULL;
        fh->finfo.wslua_info->wslua_data = NULL;
        g_free(fh->finfo.wslua_info);
        fh->finfo.wslua_info = NULL;
    }
    fh->finfo.dump_open = NULL;

    if (fh->file_type != WTAP_FILE_TYPE_SUBTYPE_UNKNOWN)
        wtap_deregister_file_type_subtype(fh->file_type);

    if (fh->is_reader && wtap_has_open_info(fh->finfo.short_name)) {
        wtap_deregister_open_info(fh->finfo.short_name);
    }

    fh->registered = FALSE;

    return 0;
}

/* The folllowing macros generate setter functions for Lua, for the following Lua
   function references in _wslua_filehandler struct:
    int read_open_ref;
    int read_ref;
    int seek_read_ref;
    int read_close_ref;
    int seq_read_close_ref;
    int can_write_encap_ref;
    int write_open_ref;
    int write_ref;
    int write_close_ref;
*/

/* WSLUA_ATTRIBUTE FileHandler_read_open WO The Lua function to be called when Wireshark opens a file for reading.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    The purpose of the Lua function set to this `read_open` field is to check if the file Wireshark is opening is of its type,
    for example by checking for magic numbers or trying to parse records in the file, etc.  The more can be verified
    the better, because Wireshark tries all file readers until it finds one that accepts the file, so accepting an
    incorrect file prevents other file readers from reading their files.

    The called Lua function should return true if the file is its type (it accepts it), false if not.  The Lua
    function must also set the File offset position (using `file:seek()`) to where it wants it to be for its first
    `read()` call.
    */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read_open);

/* WSLUA_ATTRIBUTE FileHandler_read WO The Lua function to be called when Wireshark wants to read a packet from the file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object
        3. A `FrameInfo` object

    The purpose of the Lua function set to this `read` field is to read the next packet from the file, and setting the parsed/read
    packet into the frame buffer using `FrameInfo.data = foo` or `FrameInfo:read_data()`.

    The called Lua function should return the file offset/position number where the packet begins, or false if it hit an
    error.  The file offset will be saved by Wireshark and passed into the set `seek_read()` Lua function later. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read);

/* WSLUA_ATTRIBUTE FileHandler_seek_read WO The Lua function to be called when Wireshark wants to read a packet from the file at the given offset.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object
        3. A `FrameInfo` object
        4. The file offset number previously set by the `read()` function call
 */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,seek_read);

/* WSLUA_ATTRIBUTE FileHandler_read_close WO The Lua function to be called when Wireshark wants to close the read file completely.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    It is not necessary to set this field to a Lua function - FileHandler can be registered without doing so - it
    is available in case there is memory/state to clear in your script when the file is closed. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,read_close);

/* WSLUA_ATTRIBUTE FileHandler_seq_read_close WO The Lua function to be called when Wireshark wants to close the sequentially-read file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfo` object

    It is not necessary to set this field to a Lua
    function - FileHandler can be registered without doing so - it is available in case there is memory/state to clear in your script
    when the file is closed for the sequential reading portion.  After this point, there will be no more calls to `read()`, only `seek_read()`. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,seq_read_close);


/* WSLUA_ATTRIBUTE FileHandler_can_write_encap WO The Lua function to be called when Wireshark wants to write a file,
    by checking if this file writer can handle the wtap packet encapsulation(s).

    When later called by Wireshark, the Lua function will be given a Lua number, which matches one of the encapsulations
    in the Lua `wtap_encaps` table.  This might be the `wtap_encap.PER_PACKET` number, meaning the capture contains multiple
    encapsulation types, and the file reader should only return true if it can handle multiple encap types in one file. The
    function will then be called again, once for each encap type in the file, to make sure it can write each one.

    If the Lua file writer can write the given type of encapsulation into a file, then it returns the boolean true, else false. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,can_write_encap);

/* WSLUA_ATTRIBUTE FileHandler_write_open WO The Lua function to be called when Wireshark opens a file for writing.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object

    The purpose of the Lua function set to this `write_open` field is similar to the read_open callback function:
    to initialize things necessary for writing the capture to a file. For example, if the output file format has a
    file header, then the file header should be written within this write_open function.

    The called Lua function should return true on success, or false if it hit an error.

    Also make sure to set the `FileHandler.write` (and potentially `FileHandler.write_close`) functions before
    returning true from this function. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write_open);

/* WSLUA_ATTRIBUTE FileHandler_write WO The Lua function to be called when Wireshark wants to write a packet to the file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object
        3. A `FrameInfoConst` object of the current frame/packet to be written

    The purpose of the Lua function set to this `write` field is to write the next packet to the file.

    The called Lua function should return true on success, or false if it hit an error. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write);

/* WSLUA_ATTRIBUTE FileHandler_write_close WO The Lua function to be called when Wireshark wants to close the written file.

    When later called by Wireshark, the Lua function will be given:
        1. A `File` object
        2. A `CaptureInfoConst` object

    It is not necessary to set this field to a Lua function - `FileHandler` can be registered without doing so - it is available
    in case there is memory/state to clear in your script when the file is closed. */
WSLUA_ATTRIBUTE_FUNC_SETTER(FileHandler,write_close);

/* generate other member accessors setters/getters */

/* WSLUA_ATTRIBUTE FileHandler_type RO The internal file type.  This is automatically set with a new
    number when the FileHandler is registered. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FileHandler,type,file_type);

/* WSLUA_ATTRIBUTE FileHandler_extensions RW One or more file extensions that this file type usually uses.

    For readers using heuristics to determine file type, Wireshark will try the readers of the file's
    extension first, before trying other readers.  But ultimately Wireshark tries all file readers
    for any file extension, until it finds one that accepts the file. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(FileHandler,extensions,finfo.additional_file_extensions);
WSLUA_ATTRIBUTE_NAMED_STRING_SETTER(FileHandler,extensions,finfo.additional_file_extensions,TRUE);

/* WSLUA_ATTRIBUTE FileHandler_writing_must_seek RW true if the ability to seek is required when writing
    this file format, else false.

    This will be checked by Wireshark when writing out to compressed
    file formats, because seeking is not possible with compressed files. Usually a file writer only
    needs to be able to seek if it needs to go back in the file to change something, such as a block or
    file length value earlier in the file. */
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(FileHandler,writing_must_seek,finfo.writing_must_seek);

/* WSLUA_ATTRIBUTE FileHandler_writes_name_resolution RW true if the file format supports name resolution
    records, else false. */
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(FileHandler,writes_name_resolution,finfo.has_name_resolution);
WSLUA_ATTRIBUTE_NAMED_BOOLEAN_SETTER(FileHandler,writes_name_resolution,finfo.has_name_resolution);

/* WSLUA_ATTRIBUTE FileHandler_supported_comment_types RW set to the bit-wise OR'ed number representing
    the type of comments the file writer supports writing, based on the numbers in the `wtap_comments` table. */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(FileHandler,supported_comment_types,finfo.supported_comment_types);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(FileHandler,supported_comment_types,finfo.supported_comment_types,guint32);

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES FileHandler_attributes[] = {
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read_open),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,seek_read),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,read_close),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,seq_read_close),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,can_write_encap),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write_open),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write),
    WSLUA_ATTRIBUTE_WOREG(FileHandler,write_close),
    WSLUA_ATTRIBUTE_ROREG(FileHandler,type),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,extensions),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,writing_must_seek),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,writes_name_resolution),
    WSLUA_ATTRIBUTE_RWREG(FileHandler,supported_comment_types),
    { NULL, NULL, NULL }
};

WSLUA_METHODS FileHandler_methods[] = {
    WSLUA_CLASS_FNREG(FileHandler,new),
    { NULL, NULL }
};

WSLUA_META FileHandler_meta[] = {
    WSLUA_CLASS_MTREG(FileHandler,tostring),
    { NULL, NULL }
};

int FileHandler_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(FileHandler);
    WSLUA_REGISTER_ATTRIBUTES(FileHandler);
    return 0;
}
