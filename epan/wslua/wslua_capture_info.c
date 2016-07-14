/*
 * wslua_capture_info.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for capture file data and meta-data.
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

#include <epan/addr_resolv.h>
#include <wiretap/pcapng.h>


/* WSLUA_CONTINUE_MODULE File */


WSLUA_CLASS_DEFINE(CaptureInfo,FAIL_ON_NULL_OR_EXPIRED("CaptureInfo"));
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

CaptureInfo* push_CaptureInfo(lua_State* L, wtap *wth, const gboolean first_time) {
    CaptureInfo f;

    if (!wth) {
        luaL_error(L, "Internal error: wth is NULL!");
        return NULL;
    }

    f = (CaptureInfo) g_malloc0(sizeof(struct _wslua_captureinfo));
    f->wth = wth;
    f->wdh = NULL;
    f->expired = FALSE;

    if (first_time) {
        /* XXX: need to do this? */
        wth->file_encap = WTAP_ENCAP_UNKNOWN;
        wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
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
        lua_pushfstring(L, "CaptureInfo: file_type_subtype=%d, snapshot_length=%d, pkt_encap=%d, file_tsprec='%s'",
            wth->file_type_subtype, wth->snapshot_length, wth->phdr.pkt_encap, wth->file_tsprec);
    }

    WSLUA_RETURN(1); /* String of debug information. */
}


static int CaptureInfo__gc(lua_State* L) {
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
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfo,time_precision,wth->file_tsprec);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(CaptureInfo,time_precision,wth->file_tsprec,int);

/* WSLUA_ATTRIBUTE CaptureInfo_snapshot_length RW The maximum packet length that could be recorded.

    Setting it to `0` means unknown.  Wireshark cannot handle anything bigger than 65535 bytes.
 */
WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(CaptureInfo,snapshot_length,wth->snapshot_length);
WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(CaptureInfo,snapshot_length,wth->snapshot_length,guint);

/* WSLUA_ATTRIBUTE CaptureInfo_comment RW A string comment for the whole capture file,
    or nil if there is no `comment`. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_NTH_STRING_GETTER(CaptureInfo,comment,wth->shb_hdrs,OPT_COMMENT);
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_NTH_STRING_SETTER(CaptureInfo,comment,wth->shb_hdrs,OPT_COMMENT);

/* WSLUA_ATTRIBUTE CaptureInfo_hardware RW A string containing the description of
    the hardware used to create the capture, or nil if there is no `hardware` string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfo,hardware,wth->shb_hdrs,OPT_SHB_HARDWARE);
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_SETTER(CaptureInfo,hardware,wth->shb_hdrs,OPT_SHB_HARDWARE);

/* WSLUA_ATTRIBUTE CaptureInfo_os RW A string containing the name of
    the operating system used to create the capture, or nil if there is no `os` string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfo,os,wth->shb_hdrs,OPT_SHB_OS);
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_SETTER(CaptureInfo,os,wth->shb_hdrs,OPT_SHB_OS);

/* WSLUA_ATTRIBUTE CaptureInfo_user_app RW A string containing the name of
    the application used to create the capture, or nil if there is no `user_app` string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfo,user_app,wth->shb_hdrs,OPT_SHB_USERAPPL);
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_SETTER(CaptureInfo,user_app,wth->shb_hdrs,OPT_SHB_USERAPPL);

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


WSLUA_CLASS_DEFINE(CaptureInfoConst,FAIL_ON_NULL_OR_EXPIRED("CaptureInfoConst"));
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

CaptureInfoConst* push_CaptureInfoConst(lua_State* L, wtap_dumper *wdh) {
    CaptureInfoConst f;

    if (!wdh) {
        luaL_error(L, "Internal error: wdh is NULL!");
        return NULL;
    }

    f = (CaptureInfoConst) g_malloc0(sizeof(struct _wslua_captureinfo));
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
        lua_pushfstring(L, "CaptureInfoConst: file_type_subtype=%d, snaplen=%d, encap=%d, compressed=%d, file_tsprec='%s'",
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
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfoConst,comment,wth->shb_hdrs,OPT_COMMENT);

/* WSLUA_ATTRIBUTE CaptureInfoConst_hardware RO A string containing the description of
    the hardware used to create the capture, or nil if there is no hardware string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfoConst,hardware,wth->shb_hdrs,OPT_SHB_HARDWARE);

/* WSLUA_ATTRIBUTE CaptureInfoConst_os RO A string containing the name of
    the operating system used to create the capture, or nil if there is no os string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfoConst,os,wth->shb_hdrs,OPT_SHB_OS);

/* WSLUA_ATTRIBUTE CaptureInfoConst_user_app RO A string containing the name of
    the application used to create the capture, or nil if there is no user_app string. */
WSLUA_ATTRIBUTE_NAMED_OPT_BLOCK_STRING_GETTER(CaptureInfoConst,user_app,wth->shb_hdrs,OPT_SHB_USERAPPL);

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
                lua_pushlstring(L, (char*)(&ipv6_hash_list_entry->addr[0]), 16);
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

static int CaptureInfoConst__gc(lua_State* L) {
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
