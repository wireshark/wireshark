/*
 * wslua_frame_info.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for frame data and meta-data from a capture file.
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


/* WSLUA_CONTINUE_MODULE File */


WSLUA_CLASS_DEFINE(FrameInfo,FAIL_ON_NULL_OR_EXPIRED("FrameInfo"));
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

FrameInfo* push_FrameInfo(lua_State* L, struct wtap_pkthdr *phdr, Buffer* buf) {
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
static int FrameInfo__gc(lua_State* L) {
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

        /* Make sure we have enough room for the packet */
        ws_buffer_assure_space(fi->buf, len);
        memcpy(ws_buffer_start_ptr(fi->buf), s, len);
        fi->phdr->caplen = (guint32) len;
        fi->phdr->len = (guint32) len;
    }
    else
        luaL_error(L, "FrameInfo's attribute 'data' must be a Lua string");

    return 0;
}

static int FrameInfo_get_data (lua_State* L) {
    FrameInfo fi = checkFrameInfo(L,1);

    if (!fi->buf) return 0;

    lua_pushlstring(L, ws_buffer_start_ptr(fi->buf), ws_buffer_length(fi->buf));

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

WSLUA_CLASS_DEFINE(FrameInfoConst,FAIL_ON_NULL_OR_EXPIRED("FrameInfo"));
/*
    A constant FrameInfo object, passed into Lua as an argument by the FileHandler write
    callback function.  This has similar attributes/properties as FrameInfo, but the fields can
    only be read from, not written to.

    @since 1.11.3
 */

FrameInfoConst* push_FrameInfoConst(lua_State* L, const struct wtap_pkthdr *phdr, const guint8 *pd) {
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
static int FrameInfoConst__gc(lua_State* L) {
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
