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

#include "wslua_file_common.h"

#include <errno.h>
#include <wiretap/file_wrappers.h>

#define MAX_LINE_LENGTH            65536

/* WSLUA_MODULE File Custom file format reading/writing

   The classes/functions defined in this section allow you to create your own
   custom Lua-based "capture" file reader, or writer, or both.

   @since 1.11.3
 */


WSLUA_CLASS_DEFINE(File,FAIL_ON_NULL_OR_EXPIRED("File"));
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
   has a WFILE_T member, but we can't only store its pointer here because
   dump operations need the whole thing to write out with. Ugh. */
File* push_File(lua_State* L, FILE_T ft) {
    File f = (File) g_malloc(sizeof(struct _wslua_file));
    f->file = ft;
    f->wdh = NULL;
    f->expired = FALSE;
    return pushFile(L,f);
}

File* push_Wdh(lua_State* L, wtap_dumper *wdh) {
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

/**
 * Attempts to read one line from the file. The actual data read is pushed on
 * the stack (or nil on EOF).
 */
static int File_read_line(lua_State *L, FILE_T ft) {
    static gchar linebuff[MAX_LINE_LENGTH];
    gint64 pos_before = file_tell(ft);
    gint length = 0;

    if (file_gets(linebuff, MAX_LINE_LENGTH, ft) == NULL) {
        /* No characters found, or error */
        /* *err = file_error(ft, err_info); */
        /* io.lines() and file:read() requires nil on EOF */
        lua_pushnil(L);
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

/**
 * Reads some data and returns the number of bytes read.
 * The actual data (possibly an empty string) is pushed on the Lua stack.
 */
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
static int File__gc(lua_State* L) {
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


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
