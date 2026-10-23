/*
 * wslua_address.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2011, Stig Bjorlykke <stig@bjorlykke.org>
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"

#include <epan/addr_resolv.h>

/* WSLUA_CONTINUE_MODULE Pinfo */


WSLUA_CLASS_DEFINE_INLINE_BASE(Address,NOP); /* Represents an address. */

/* Copies the address, including its data, which is stored in the userdata
 * after the address itself so that no __gc metamethod is needed to free it. */
Address pushAddress(lua_State* L, Address v) {
    Address p;
    luaL_checkstack(L,2,"Unable to grow stack\n");
    p = (Address)lua_newuserdata(L, sizeof(address) + v->len);
    if (v->len > 0) {
        memcpy(p + 1, v->data, v->len);
        set_address(p, v->type, v->len, p + 1);
    } else {
        set_address(p, v->type, 0, NULL);
    }
    luaL_getmetatable(L, "Address");
    lua_setmetatable(L, -2);
    return p;
}

WSLUA_CONSTRUCTOR Address_ip(lua_State* L) {
    /* Creates an Address Object representing an IPv4 address. */

#define WSLUA_ARG_Address_ip_HOSTNAME 1 /* The address or name of the IP host. */
    address addr;
    uint32_t ip_addr;
    const char* name = luaL_checkstring(L,WSLUA_ARG_Address_ip_HOSTNAME);

    if (! get_host_ipaddr(name, &ip_addr)) {
        ip_addr = 0;
    }

    set_address(&addr, AT_IPv4, 4, &ip_addr);
    pushAddress(L,&addr);
    WSLUA_RETURN(1); /* The Address object. */
}

WSLUA_CONSTRUCTOR Address_ipv6(lua_State* L) {
    /* Creates an Address Object representing an IPv6 address. */

#define WSLUA_ARG_Address_ipv6_HOSTNAME 1 /* The address or name of the IP host. */
    address addr;
    ws_in6_addr ip_addr;
    const char* name = luaL_checkstring(L,WSLUA_ARG_Address_ipv6_HOSTNAME);

    if (!get_host_ipaddr6(name, &ip_addr)) {
        memset(&ip_addr, 0, sizeof(ip_addr));
    }

    set_address(&addr, AT_IPv6, sizeof(ip_addr.bytes), &ip_addr.bytes);
    pushAddress(L,&addr);
    WSLUA_RETURN(1); /* The Address object */
}

WSLUA_CONSTRUCTOR Address_ether(lua_State *L) {
    /* Creates an Address Object representing an Ethernet address. */

#define WSLUA_ARG_Address_ether_ETH 1 /* The Ethernet address. */
    address addr;
    const char *name = luaL_checkstring(L, WSLUA_ARG_Address_ether_ETH);
    uint8_t eth_buf[6];

    if(!str_to_eth(name, &eth_buf))
        memset(eth_buf, 0, sizeof(eth_buf));

    set_address(&addr, AT_ETHER, sizeof(eth_buf), eth_buf);
    pushAddress(L, &addr);
    WSLUA_RETURN(1); /* The Address object. */
}

#if 0
/* TODO */
static int Address_ss7(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_sna(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_atalk(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_vines(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_osi(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_arcnet(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_fc(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_string(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_eui64(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_uri(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
static int Address_tipc(lua_State* L) {
    address addr;

    /* set_address() */

    pushAddress(L,&addr);
    return 1;
}
#endif

/* Read-only attributes for debugger introspection. Expose the raw
 * enum/length so the Variables view can show structured metadata next
 * to __tostring. */

/* Map address_type enum to its "AT_*" identifier for the type_name
 * attribute. Values not listed fall back to "unknown" — the address
 * module header is the source of truth for the full set. */
static const char *address_type_to_string(address_type t) {
    switch (t) {
        case AT_NONE:      return "AT_NONE";
        case AT_ETHER:     return "AT_ETHER";
        case AT_IPv4:      return "AT_IPv4";
        case AT_IPv6:      return "AT_IPv6";
        case AT_IPX:       return "AT_IPX";
        case AT_FC:        return "AT_FC";
        case AT_FCWWN:     return "AT_FCWWN";
        case AT_STRINGZ:   return "AT_STRINGZ";
        case AT_EUI64:     return "AT_EUI64";
        case AT_IB:        return "AT_IB";
        case AT_AX25:      return "AT_AX25";
        case AT_VINES:     return "AT_VINES";
        case AT_NUMERIC:   return "AT_NUMERIC";
        case AT_MCTP:      return "AT_MCTP";
        case AT_ILNP_NID:  return "AT_ILNP_NID";
        case AT_ILNP_L64:  return "AT_ILNP_L64";
        case AT_ILNP_ILV:  return "AT_ILNP_ILV";
        default:           return "unknown";
    }
}

/* WSLUA_ATTRIBUTE Address_type RO The address type as an integer from
   the address_type enum (e.g. AT_IPv4 == 2, AT_IPv6 == 3, AT_ETHER
   == 1). AT_NONE (0) indicates an unset/empty address. Use
   `Address.type_name` for the human-readable "AT_*" name. */
WSLUA_ATTRIBUTE_GET(Address,type, {
    lua_pushinteger(L, obj->type);
});

/* WSLUA_ATTRIBUTE Address_type_name RO Human-readable "AT_*" string
   matching `Address.type` (e.g. "AT_IPv4", "AT_ETHER"). Returns
   "unknown" for enum values this build does not recognise. */
WSLUA_ATTRIBUTE_GET(Address,type_name, {
    lua_pushstring(L, address_type_to_string(obj->type));
});

/* WSLUA_ATTRIBUTE Address_length RO The address length in bytes (4 for
   IPv4, 16 for IPv6, 6 for Ethernet, ...). */
WSLUA_ATTRIBUTE_GET(Address,length, {
    lua_pushinteger(L, obj->len);
});

WSLUA_ATTRIBUTES Address_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(Address,type),
    WSLUA_ATTRIBUTE_ROREG(Address,type_name),
    WSLUA_ATTRIBUTE_ROREG(Address,length),
    { NULL, NULL, NULL }
};

WSLUA_METHODS Address_methods[] = {
    WSLUA_CLASS_FNREG(Address,ip),
    WSLUA_CLASS_FNREG_ALIAS(Address,ipv4,ip),
    WSLUA_CLASS_FNREG(Address,ipv6),
    WSLUA_CLASS_FNREG(Address,ether),
#if 0
    WSLUA_CLASS_FNREG_ALIAS(Address,ss7pc,ss7),
    WSLUA_CLASS_FNREG(Address,sna},
    WSLUA_CLASS_FNREG(Address,atalk),
    WSLUA_CLASS_FNREG(Address,vines),
    WSLUA_CLASS_FNREG(Address,osi),
    WSLUA_CLASS_FNREG(Address,arcnet),
    WSLUA_CLASS_FNREG(Address,fc),
    WSLUA_CLASS_FNREG(Address,string),
    WSLUA_CLASS_FNREG(Address,eui64),
    WSLUA_CLASS_FNREG(Address,uri),
    WSLUA_CLASS_FNREG(Address,tipc),
#endif
    { NULL, NULL }
};

WSLUA_METAMETHOD Address__tostring(lua_State* L) {
    Address addr = checkAddress(L,1);
    char *str = address_to_display(NULL, addr);

    lua_pushstring(L, str);

    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* The string representing the address. */
}

WSLUA_METAMETHOD Address__eq(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    bool result = false;

    if (addresses_equal(addr1, addr2))
        result = true;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD Address__le(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    bool result = false;

    if (cmp_address(addr1, addr2) <= 0)
        result = true;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD Address__lt(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    bool result = false;

    if (cmp_address(addr1, addr2) < 0)
        result = true;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_META Address_meta[] = {
    WSLUA_CLASS_MTREG(Address,tostring),
    WSLUA_CLASS_MTREG(Address,eq),
    WSLUA_CLASS_MTREG(Address,le),
    WSLUA_CLASS_MTREG(Address,lt),
    { NULL, NULL }
};


int Address_register(lua_State *L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS_NOGC(Address);
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
