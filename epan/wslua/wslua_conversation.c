/*
 * wslua_conversation.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2024, Alastair Knowles <kno0001@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

/* WSLUA_CONTINUE_MODULE Pinfo */

#include "wslua.h"
#include <epan/conversation.h>

static const wslua_conv_types_t convtype_enums[] = {
    {"convtypes.NONE", CONVERSATION_NONE},
    {"convtypes.SCTP", CONVERSATION_SCTP},
    {"convtypes.TCP", CONVERSATION_TCP},
    {"convtypes.UDP", CONVERSATION_UDP},
    {"convtypes.DCCP", CONVERSATION_DCCP},
    {"convtypes.IPX", CONVERSATION_IPX},
    {"convtypes.NCP", CONVERSATION_NCP},
    {"convtypes.EXCHG", CONVERSATION_EXCHG},
    {"convtypes.DDP", CONVERSATION_DDP},
    {"convtypes.SBCCS", CONVERSATION_SBCCS},
    {"convtypes.IDP", CONVERSATION_IDP},
    {"convtypes.TIPC", CONVERSATION_TIPC},
    {"convtypes.USB", CONVERSATION_USB},
    {"convtypes.I2C", CONVERSATION_I2C},
    {"convtypes.IBQP", CONVERSATION_IBQP},
    {"convtypes.BLUETOOTH", CONVERSATION_BLUETOOTH},
    {"convtypes.TDMOP", CONVERSATION_TDMOP},
    {"convtypes.DVBCI", CONVERSATION_DVBCI},
    {"convtypes.ISO14443", CONVERSATION_ISO14443},
    {"convtypes.ISDN", CONVERSATION_ISDN},
    {"convtypes.H223", CONVERSATION_H223},
    {"convtypes.X25", CONVERSATION_X25},
    {"convtypes.IAX2", CONVERSATION_IAX2},
    {"convtypes.DLCI", CONVERSATION_DLCI},
    {"convtypes.ISUP", CONVERSATION_ISUP},
    {"convtypes.BICC", CONVERSATION_BICC},
    {"convtypes.GSMTAP", CONVERSATION_GSMTAP},
    {"convtypes.IUUP", CONVERSATION_IUUP},
    {"convtypes.DVBBBF", CONVERSATION_DVBBBF},
    {"convtypes.IWARP_MPA", CONVERSATION_IWARP_MPA},
    {"convtypes.BT_UTP", CONVERSATION_BT_UTP},
    {"convtypes.LOG", CONVERSATION_LOG},
    {"convtypes.LTP", CONVERSATION_LTP},
    {"convtypes.MCTP", CONVERSATION_MCTP},
    {"convtypes.NVME_MI", CONVERSATION_NVME_MI},
    {"convtypes.BP", CONVERSATION_BP},
    {"convtypes.SNMP", CONVERSATION_SNMP},
    {"convtypes.QUIC", CONVERSATION_QUIC},
    {"convtypes.IDN", CONVERSATION_IDN},
    {"convtypes.IP", CONVERSATION_IP},
    {"convtypes.IPV6", CONVERSATION_IPV6},
    {"convtypes.ETH", CONVERSATION_ETH},
    {"convtypes.ETH_NN", CONVERSATION_ETH_NN},
    {"convtypes.ETH_NV", CONVERSATION_ETH_NV},
    {"convtypes.ETH_IN", CONVERSATION_ETH_IN},
    {"convtypes.ETH_IV", CONVERSATION_ETH_IV},
    {"convtypes.VSPC_VMOTION", CONVERSATION_VSPC_VMOTION},
    {"convtypes.OPENVPN", CONVERSATION_OPENVPN},
    {"convtypes.PROXY", CONVERSATION_PROXY},
    {"convtypes.DNP3", CONVERSATION_DNP3},
    {NULL, CONVERSATION_NONE}
};

#define CONVTYPE_ENUM_LAST (sizeof(convtype_enums)/sizeof(wslua_conv_types_t)-1)

const wslua_conv_types_t* wslua_inspect_convtype_enum(void) {
    return convtype_enums;
}

static conversation_type str_to_convtype_enum(const char* type) {
    const wslua_conv_types_t* ts;
    for (ts = convtype_enums; ts->str; ts++) {
        if ( g_str_equal(ts->str,type) ) {
            return ts->id;
        }
    }
    return CONVERSATION_NONE;
}

static conversation_type int_to_convtype_enum(int type) {
    if (type < (int)convtype_enums[0].id || type > (int)convtype_enums[CONVTYPE_ENUM_LAST-1].id) {
        type = CONVERSATION_NONE;
    }
    return (conversation_type)type;
}

WSLUA_CLASS_DEFINE(Conversation,NOP);
/* Conversation object, used to attach conversation data or a conversation dissector */

WSLUA_METAMETHOD Conversation__eq(lua_State *L) { /* Compares two Conversation objects. */
    Conversation conv1 = checkConversation(L,1);
    Conversation conv2 = checkConversation(L,2);

    lua_pushboolean(L, conv1 == conv2);

    WSLUA_RETURN(1); /* True if both objects refer to the same underlying conversation structure. False otherwise. */
}

WSLUA_METAMETHOD Conversation__tostring(lua_State *L) {
    Conversation conv = checkConversation(L,1);
    lua_pushfstring(L, "Conversation object (%p)", conv);
    WSLUA_RETURN(1); /* A string representation of the object. */
}


/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Conversation__gc(lua_State* L _U_) {
    /* Don't free. Conversation struct managed in Wireshark */
    return 0;
}

WSLUA_CONSTRUCTOR Conversation_find(lua_State* L) {
    /* Searches for a `Conversation` instance matching criteria. If one does not exist and 'create'
       is true, one will be created, otherwise `nil` will be returned. Note that, although there are
       'first' and 'second' addresses and ports, a conversation does not distinguish between source
       or destination. These are effectively matching criteria that wireshark uses to flag a packet as
       belonging to the conversation. */

#define WSLUA_ARG_Conversation_find_FRAMENUM 1 /* The number of a frame within the conversation. If a new
                                                  conversation is created, this will be used as the first
                                                  frame of the conversation. */
#define WSLUA_ARG_Conversation_find_CTYPE 2 /* Conversation Type. One of: `convtypes.NONE`, `convtypes.SCTP`,
       `convtypes.TCP`, `convtypes.UDP`, `convtypes.DCCP`, `convtypes.IPX`, `convtypes.NCP`,
       `convtypes.EXCHG`, `convtypes.DDP`, `convtypes.SBCCS`, `convtypes.IDP`, `convtypes.TIPC`,
       `convtypes.USB`, `convtypes.I2C`, `convtypes.IBQP`, `convtypes.BLUETOOTH`, `convtypes.TDMOP`,
       `convtypes.DVBCI`, `convtypes.ISO14443`, `convtypes.ISDN`, `convtypes.H223`, `convtypes.X25`,
       `convtypes.IAX2`, `convtypes.DLCI`, `convtypes.ISUP`, `convtypes.BICC`, `convtypes.GSMTAP`,
       `convtypes.IUUP`, `convtypes.DVBBBF`, `convtypes.IWARP_MPA`, `convtypes.BT_UTP`, `convtypes.LOG`,
       `convtypes.LTP`, `convtypes.MCTP`, `convtypes.NVME_MI`, `convtypes.BP`, `convtypes.SNMP`,
       `convtypes.QUIC`, `convtypes.IDN`, `convtypes.IP`, `convtypes.IPV6`, `convtypes.ETH`,
       `convtypes.ETH_NN`, `convtypes.ETH_NV`, `convtypes.ETH_IN`, `convtypes.ETH_IV`,
       `convtypes.VSPC_VMOTION`, `convtypes.OPENVPN`, `convtypes.PROXY`, `convtypes.DNP3` */

#define WSLUA_ARG_Conversation_find_ADDR1 3 /* First <<lua_class_Address,``Address``>> of the conversation. */
#define WSLUA_OPTARG_Conversation_find_ADDR2 4 /* Second <<lua_class_Address,``Address``>> of theconversation. (defaults to nil) */
#define WSLUA_OPTARG_Conversation_find_PORT1 5 /* First port. A value of `nil` or `0` is treated as 'ignore' (default) */
#define WSLUA_OPTARG_Conversation_find_PORT2 6 /* Second port. A value of `nil` or `0` is treated as 'ignore' (default) */
#define WSLUA_OPTARG_Conversation_find_CREATE 7 /* Boolean. If conversation doesn't exist, create it (default true) */

    uint32_t frameNum = wslua_checkuint32(L,WSLUA_ARG_Conversation_find_FRAMENUM);
    Address addr1 = checkAddress(L,WSLUA_ARG_Conversation_find_ADDR1);
    uint32_t port1 = wslua_optuint32(L, WSLUA_OPTARG_Conversation_find_PORT1, 0);
    uint32_t port2 = wslua_optuint32(L, WSLUA_OPTARG_Conversation_find_PORT2, 0);
    bool create = wslua_optbool(L,WSLUA_OPTARG_Conversation_find_CREATE,true);

    conversation_type ctype;
    if (lua_isnumber(L,WSLUA_ARG_Conversation_find_CTYPE)) {
        ctype = int_to_convtype_enum(wslua_checkint(L,WSLUA_ARG_Conversation_find_CTYPE));
    } else {
        ctype = str_to_convtype_enum(luaL_checkstring(L,WSLUA_ARG_Conversation_find_CTYPE));
    }

    unsigned int options = 0;

    Address addr2 = NULL;
    if (isAddress(L,WSLUA_OPTARG_Conversation_find_ADDR2)) {
        addr2 = toAddress(L,WSLUA_OPTARG_Conversation_find_ADDR2);
    } else {
        /* Port A not given. Flag the option */
        options |= NO_ADDR_B;
    }

    if (!port2) {
        /* Port B not given. Flag the option */
        options |= NO_PORT_B;
    }

    if (!port1) {
        if (!port2) {
            /* Neither port given. Flag that as an option */
            options |= NO_PORT_X | NO_PORTS;
        } else {
            /* Swap ports 1 & 2 if 2 was given, but 1 was not */
            port1 = port2;
            port2 = 0;
        }
    }


    Conversation conv = find_conversation(frameNum, addr1, addr2, ctype, port1, port2, options);

    if (conv == NULL && create) {
        int optsNew = 0;

        if (options & NO_ADDR_B) {
            optsNew |= NO_ADDR2;
        }

        if (options & NO_PORT_B) {
            optsNew |= NO_PORT2;
        }

        if (options & NO_PORT_X) {
            optsNew |= NO_PORTS;
        }

        conv = conversation_new(frameNum, addr1, addr2, ctype, port1, port2, optsNew);
    }

    if (conv) {
        pushConversation(L, conv);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The found or created <<lua_class_Conversation,`Conversation`>> instance. */
}

WSLUA_CONSTRUCTOR Conversation_find_by_id(lua_State* L) {
    /* Searches for a `Conversation` object by id. If one does not exist and 'create' is true, one
       will be created, otherwise `nil` will be returned. This is typically used if a protocol
       encapsulates multiple 'sessions' or 'channels' in a single connection, and denotes this with
       a 'channel id' or equivalent. */
#define WSLUA_ARG_Conversation_find_by_id_FRAMENUM 1 /* The number of a frame within the conversation. If a new
                                                        conversation is created, this will be used as the first
                                                        frame of the conversation. */
#define WSLUA_ARG_Conversation_find_by_id_CTYPE 2 /* Conversation Type. One of: `convtypes.NONE`,
       `convtypes.SCTP`, `convtypes.TCP`, `convtypes.UDP`, `convtypes.DCCP`, `convtypes.IPX`, `convtypes.NCP`,
       `convtypes.EXCHG`, `convtypes.DDP`, `convtypes.SBCCS`, `convtypes.IDP`, `convtypes.TIPC`,
       `convtypes.USB`, `convtypes.I2C`, `convtypes.IBQP`, `convtypes.BLUETOOTH`, `convtypes.TDMOP`,
       `convtypes.DVBCI`, `convtypes.ISO14443`, `convtypes.ISDN`, `convtypes.H223`, `convtypes.X25`,
       `convtypes.IAX2`, `convtypes.DLCI`, `convtypes.ISUP`, `convtypes.BICC`, `convtypes.GSMTAP`,
       `convtypes.IUUP`, `convtypes.DVBBBF`, `convtypes.IWARP_MPA`, `convtypes.BT_UTP`, `convtypes.LOG`,
       `convtypes.LTP`, `convtypes.MCTP`, `convtypes.NVME_MI`, `convtypes.BP`, `convtypes.SNMP`,
       `convtypes.QUIC`, `convtypes.IDN`, `convtypes.IP`, `convtypes.IPV6`, `convtypes.ETH`,
       `convtypes.ETH_NN`, `convtypes.ETH_NV`, `convtypes.ETH_IN`, `convtypes.ETH_IV`,
       `convtypes.VSPC_VMOTION`, `convtypes.OPENVPN`, `convtypes.PROXY`, `convtypes.DNP3` */
#define WSLUA_ARG_Conversation_find_by_id_ID 3 /* Conversation or session specific ID */
#define WSLUA_OPTARG_Conversation_find_by_id_CREATE 4 /* Boolean. If conversation doesn't exist, create it (default true) */

    uint32_t frameNum = wslua_checkuint32(L,WSLUA_ARG_Conversation_find_by_id_FRAMENUM);
    uint32_t idNum = wslua_checkuint32(L,WSLUA_ARG_Conversation_find_by_id_ID);
    bool create = wslua_optbool(L, WSLUA_OPTARG_Conversation_find_by_id_CREATE, true);

    conversation_type ctype;
    if (lua_isnumber(L,WSLUA_ARG_Conversation_find_CTYPE)) {
        ctype = int_to_convtype_enum(wslua_checkint(L,WSLUA_ARG_Conversation_find_CTYPE));
    } else {
        ctype = str_to_convtype_enum(luaL_checkstring(L,WSLUA_ARG_Conversation_find_CTYPE));
    }

    Conversation conv = find_conversation_by_id(frameNum, ctype, idNum);

    if ((conv == NULL) && create) {
        conv = conversation_new_by_id(frameNum, ctype, idNum);
    }

    if (conv) {
        pushConversation(L, conv);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The found or created `Conversation` instance. */
}

WSLUA_CONSTRUCTOR Conversation_find_from_pinfo(lua_State* L) {
    /* Searches for a `Conversation` object matching a pinfo. If one does not exist and 'create' is
       true, one will be created, otherwise `nil` will be returned. Note that this is a shortcut for
       `Conversation.find()`, where a pinfo structure is conveniently decomposed into individual
       components for you. If you're not sure which `Conversation.find` method to use, most of the
       time this will the the correct choice. */
#define WSLUA_ARG_Conversation_find_from_pinfo_PINFO 1 /* A <<lua_class_Pinfo, `Pinfo`>> object. */
#define WSLUA_OPTARG_Conversation_find_from_pinfo_CREATE 2 /* Boolean. If conversation doesn't exist, create it (default true) */

    Pinfo p = checkPinfo(L,WSLUA_ARG_Conversation_find_from_pinfo_PINFO);
    bool create = wslua_optbool(L,WSLUA_OPTARG_Conversation_find_from_pinfo_CREATE,true);

    Conversation conv;

    if (create) {
        conv = find_or_create_conversation(p->ws_pinfo);
    } else {
        conv = find_conversation_pinfo(p->ws_pinfo, 0);
    }

    if (conv) {
        pushConversation(L, conv);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The found or created `Conversation` instance. */
}

static bool wslua_conv_cleanup_cb(wmem_allocator_t *alloc, wmem_cb_event_t event, void* data) {
    /* Conversation data is managed by wmem_file_scope(). This callback ensures the
     * corresponding Lua table is correctly released. */
    (void)alloc;
    if (event == WMEM_CB_FREE_EVENT) {
        lua_State* L = wslua_state();
        wslua_conv_data_t *cd = (wslua_conv_data_t *)data;
        if (L != NULL) {
            luaL_unref(L, LUA_REGISTRYINDEX, cd->data_ref);
        }
    }
    return false;
}

WSLUA_METAMETHOD Conversation__newindex(lua_State* L) {
    /* Sets protocol data for a specific protocol */
#define WSLUA_ARG_Conversation__newindex_INDEX 2 /* The protocol index to set. Must be a <<lua_class_Proto,`Proto`>> */
#define WSLUA_ARG_Conversation__newindex_VALUE 3 /* The protocol data to set (any valid lua object) */
    Conversation conv = checkConversation(L,1);
    Proto proto = checkProto(L,WSLUA_ARG_Conversation__newindex_INDEX);

    luaL_checkany(L, WSLUA_ARG_Conversation__newindex_VALUE);

    wslua_conv_data_t *cd = conversation_get_proto_data(conv, proto->hfid);

    if (lua_isnoneornil(L, WSLUA_ARG_Conversation__newindex_VALUE)) {
        if (cd != NULL) {
            luaL_unref(L, LUA_REGISTRYINDEX, cd->data_ref);
            cd->data_ref = LUA_NOREF;
        }
        return 0;
    }

    lua_settop(L, WSLUA_ARG_Conversation__newindex_VALUE);

    if (cd == NULL) {
        /* No conversation data set. Create new data saver now. */
        cd = wmem_alloc(wmem_file_scope(), sizeof(wslua_conv_data_t));
        wmem_register_callback(wmem_file_scope(), wslua_conv_cleanup_cb, cd);

        cd->conv = conv;
        cd->data_ref = LUA_NOREF;

        conversation_add_proto_data(conv, proto->hfid, cd);
    }

    if (cd->data_ref == LUA_NOREF) {
        cd->data_ref = luaL_ref(L, LUA_REGISTRYINDEX); /* Automatically pushes 'top' */
    } else {
        /* Update value */
        lua_rawseti(L, LUA_REGISTRYINDEX, cd->data_ref);
    }

    return 0;
}

WSLUA_METAMETHOD Conversation__index(lua_State* L) {
    /* Get protocol data for a specific protocol */
#define WSLUA_ARG_Conversation__index_INDEX 2 /* The protocol index to get. Must be a <<lua_class_Proto,`Proto`>> */
    Conversation conv = checkConversation(L,1);
    Proto proto = checkProto(L,WSLUA_ARG_Conversation__index_INDEX);

    wslua_conv_data_t *cd = conversation_get_proto_data(conv, proto->hfid);

    if (cd == NULL || cd->data_ref == LUA_NOREF) {
        lua_pushnil(L);
    } else {
        lua_rawgeti(L, LUA_REGISTRYINDEX, cd->data_ref);
    }

    WSLUA_RETURN(1); /* Previously assigned conversation data, or `nil`. */
}

/* WSLUA_ATTRIBUTE Conversation_dissector WO Sets the dissector to be used for the conversation.
   Accepted types are either a <<lua_class_Proto,`Proto`>> with assigned dissector, or a <<lua_class_Dissector,`Dissector`>>. */
WSLUA_ATTR_SET Conversation_set_dissector(lua_State* L) {
    Conversation conv = checkConversation(L,1);
    Dissector handle;

    if (isProto(L,2)) {
        Proto p = toProto(L,2);
        handle = p->handle;

        if (!handle) {
            luaL_error(L,"Proto %s has no registered dissector", p->name ? p->name : "<UNKNOWN>");
            return 0;
        }
    } else if (isDissector(L,2)) {
        handle = toDissector(L,2);
    } else {
        luaL_error(L,"Assigned data type must be either a Proto or Dissector");
        return 0;
    }

    conversation_set_dissector(conv,handle);

    return 0;
};

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES Conversation_attributes[] = {
    WSLUA_ATTRIBUTE_WOREG(Conversation,dissector),
    { NULL, NULL, NULL }
};

WSLUA_METHODS Conversation_methods[] = {
    WSLUA_CLASS_FNREG(Conversation,find),
    WSLUA_CLASS_FNREG(Conversation,find_by_id),
    WSLUA_CLASS_FNREG(Conversation,find_from_pinfo),
    { NULL, NULL }
};

WSLUA_META Conversation_meta[] = {
    WSLUA_CLASS_MTREG(Conversation,eq),
    WSLUA_CLASS_MTREG(Conversation,tostring),
    WSLUA_CLASS_MTREG(Conversation,newindex),
    WSLUA_CLASS_MTREG(Conversation,index),
    { NULL, NULL }
};

int Conversation_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS(Conversation);

    return 0;
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
