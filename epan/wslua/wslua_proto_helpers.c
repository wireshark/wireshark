/*
 *  wslua_proto_helpers.c
 * Function helpers for protocol specific functionality
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSLUA

#include "wslua.h"
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-tls-utils.h>


static unsigned
wslua_dissect_tcp_get_pdu_len(packet_info* pinfo, tvbuff_t* tvb,
    int offset, void* data)
{
    /* WARNING: called from a TRY block, do not call luaL_error! */
    struct _wslua_func_saver* fs = (struct _wslua_func_saver*)data;
    lua_State* L = fs->state;
    int pdu_len = 0;

    lua_settop(L, 0);
    lua_rawgeti(L, LUA_REGISTRYINDEX, fs->get_len_ref);

    if (lua_isfunction(L, 1)) {

        push_Tvb(L, tvb);
        push_Pinfo(L, pinfo);
        lua_pushinteger(L, offset);

        if (lua_pcall(L, 3, 1, 0)) {
            THROW_LUA_ERROR("Lua Error in dissect_tcp_pdus get_len_func: %s", lua_tostring(L, -1));
        }
        else {
            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the pdu_len */
                pdu_len = wslua_toint(L, -1);
                lua_pop(L, 1);
            }
            else {
                THROW_LUA_ERROR("Lua Error dissect_tcp_pdus: get_len_func did not return a Lua number of the PDU length");
            }
        }

    }
    else {
        REPORT_DISSECTOR_BUG("Lua Error in dissect_tcp_pdus: did not find the get_len_func dissector");
    }

    return pdu_len;
}

static int
wslua_dissect_tcp_dissector(tvbuff_t* tvb, packet_info* pinfo,
    proto_tree* tree, void* data)
{
    /* WARNING: called from a TRY block, do not call luaL_error! */
    struct _wslua_func_saver* fs = (struct _wslua_func_saver*)data;
    lua_State* L = fs->state;
    int consumed_bytes = 0;

    lua_settop(L, 0);
    lua_rawgeti(L, LUA_REGISTRYINDEX, fs->dissect_ref);

    if (lua_isfunction(L, 1)) {

        push_Tvb(L, tvb);
        push_Pinfo(L, pinfo);
        /* XXX: not sure if it's kosher to just use the tree as the item */
        push_TreeItem(L, tree, (proto_item*)tree);

        if (lua_pcall(L, 3, 1, 0)) {
            THROW_LUA_ERROR("dissect_tcp_pdus dissect_func: %s", lua_tostring(L, -1));
        }
        else {
            /* if the Lua dissector reported the consumed bytes, pass it to our caller */
            if (lua_isnumber(L, -1)) {
                /* we got the consumed bytes or the missing bytes as a negative number */
                consumed_bytes = wslua_toint(L, -1);
                lua_pop(L, 1);
            }
        }

    }
    else {
        REPORT_DISSECTOR_BUG("dissect_tcp_pdus: did not find the dissect_func dissector");
    }

    return consumed_bytes;
}


WSLUA_FUNCTION wslua_dissect_tcp_pdus(lua_State* L) {
    /* Make the TCP-layer invoke the given Lua dissection function for each
       PDU in the TCP segment, of the length returned by the given get_len_func
       function.

       This function is useful for protocols that run over TCP and that are
       either a fixed length always, or have a minimum size and have a length
       field encoded within that minimum portion that identifies their full
       length. For such protocols, their protocol dissector function can invoke
       this `dissect_tcp_pdus()` function to make it easier to handle dissecting
       their protocol's messages (i.e., their protocol data unit (PDU)). This
       function shouild not be used for protocols whose PDU length cannot be
       determined from a fixed minimum portion, such as HTTP or Telnet.
     */
#define WSLUA_ARG_dissect_tcp_pdus_TVB 1 /* The Tvb buffer to dissect PDUs from. */
#define WSLUA_ARG_dissect_tcp_pdus_TREE 2 /* `TreeItem` object passed to the `dissect_func`. */
#define WSLUA_ARG_dissect_tcp_pdus_MIN_HEADER_SIZE 3 /* The number of bytes
                        in the fixed-length part of the PDU. */
#define WSLUA_ARG_dissect_tcp_pdus_GET_LEN_FUNC 4 /* A Lua function that will be
                        called for each PDU, to determine the full length of the
                        PDU. The called function will be given (1) the `Tvb` object
                        of the whole `Tvb` (possibly reassembled), (2) the `Pinfo` object,
                        and (3) an offset number of the index of the first byte
                        of the PDU (i.e., its first header byte). The Lua function
                        must return a Lua number of the full length of the PDU. */
#define WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC 5 /* A Lua function that will be
                        called for each PDU, to dissect the PDU. The called
                        function will be given (1) the `Tvb` object of the PDU's
                        `Tvb` (possibly reassembled), (2) the `Pinfo` object,
                        and (3) the `TreeItem` object. The Lua function must
                        return a Lua number of the number of bytes read/handled,
                        which would typically be the `Tvb:len()`.*/
#define WSLUA_OPTARG_dissect_tcp_pdus_DESEGMENT 6 /* Whether to reassemble PDUs
                        crossing TCP segment boundaries or not. (default=true) */
    Tvb tvb = checkTvb(L, WSLUA_ARG_dissect_tcp_pdus_TVB);
    TreeItem ti = checkTreeItem(L, WSLUA_ARG_dissect_tcp_pdus_TREE);
    unsigned fixed_len = (unsigned)luaL_checkinteger(L, WSLUA_ARG_dissect_tcp_pdus_MIN_HEADER_SIZE);
    bool proto_desegment = wslua_optbool(L, WSLUA_OPTARG_dissect_tcp_pdus_DESEGMENT, true);

    if (!lua_pinfo) {
        luaL_error(L, "dissect_tcp_pdus can only be invoked while in a dissect function");
        return 0;
    }

    if (lua_isfunction(L, WSLUA_ARG_dissect_tcp_pdus_GET_LEN_FUNC) &&
        lua_isfunction(L, WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC))
    {
        /* save the Lua functions so that we can call them later */
        struct _wslua_func_saver* fs = g_new(struct _wslua_func_saver, 1);

        lua_settop(L, WSLUA_ARG_dissect_tcp_pdus_DISSECT_FUNC);

        fs->state = L;
        /* the following pops the top function and sets a ref to it in the registry */
        fs->dissect_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        fs->get_len_ref = luaL_ref(L, LUA_REGISTRYINDEX);

        /* save the passed-in function refs, so Lua's garbage collector won't
           destroy them before they get invoked */
        g_ptr_array_add(lua_outstanding_FuncSavers, fs);

        WRAP_NON_LUA_EXCEPTIONS(
            tcp_dissect_pdus(tvb->ws_tvb, lua_pinfo, ti->tree, proto_desegment,
                fixed_len, wslua_dissect_tcp_get_pdu_len,
                wslua_dissect_tcp_dissector, (void*)fs);
        )
    }
    else {
        luaL_error(L, "The third and fourth arguments need to be Lua functions");
    }
    return 0;
}



WSLUA_FUNCTION wslua_ssl_starttls_ack (lua_State* L) {
    /* TLS protocol will be started after this fame */
#define WSLUA_ARG_ssl_starttls_ack_TLS_HANDLE 1 /* the tls dissector */
#define WSLUA_ARG_ssl_starttls_ack_PINFO 2 /* The packet's <<lua_class_Pinfo,`Pinfo`>>. */
#define WSLUA_ARG_ssl_starttls_ack_APP_HANDLE 3 /* The app dissector */
    Dissector volatile tls_dissector = checkDissector(L,WSLUA_ARG_ssl_starttls_ack_TLS_HANDLE);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_ssl_starttls_ack_PINFO);
    Proto app_proto = checkProto(L, WSLUA_ARG_ssl_starttls_ack_APP_HANDLE);

    ssl_starttls_ack(tls_dissector, pinfo->ws_pinfo, app_proto->handle);

    WSLUA_RETURN(0);
}

WSLUA_FUNCTION wslua_ssl_starttls_post_ack (lua_State* L) {
    /* TLS protocol is started with this frame */
#define WSLUA_ARG_ssl_starttls_post_ack_TLS_HANDLE 1 /* the tls dissector */
#define WSLUA_ARG_ssl_starttls_post_ack_PINFO 2 /* The packet's <<lua_class_Pinfo,`Pinfo`>>. */
#define WSLUA_ARG_ssl_starttls_post_ack_APP_HANDLE 3 /* The app dissector */
    Dissector volatile tls_dissector = checkDissector(L,WSLUA_ARG_ssl_starttls_post_ack_TLS_HANDLE);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_ssl_starttls_post_ack_PINFO);
    Proto app_proto = checkProto(L, WSLUA_ARG_ssl_starttls_post_ack_APP_HANDLE);

    ssl_starttls_post_ack(tls_dissector, pinfo->ws_pinfo, app_proto->handle);

    WSLUA_RETURN(0);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
