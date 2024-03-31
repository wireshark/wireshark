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


WSLUA_CLASS_DEFINE(Address,FAIL_ON_NULL("Address")); /* Represents an address. */

WSLUA_CONSTRUCTOR Address_ip(lua_State* L) {
    /* Creates an Address Object representing an IPv4 address. */

#define WSLUA_ARG_Address_ip_HOSTNAME 1 /* The address or name of the IP host. */
    Address addr = (Address)g_malloc(sizeof(address));
    uint32_t ip_addr;
    const char* name = luaL_checkstring(L,WSLUA_ARG_Address_ip_HOSTNAME);

    if (! get_host_ipaddr(name, &ip_addr)) {
        ip_addr = 0;
    }

    alloc_address_wmem(NULL, addr, AT_IPv4, 4, &ip_addr);
    pushAddress(L,addr);
    WSLUA_RETURN(1); /* The Address object. */
}

WSLUA_CONSTRUCTOR Address_ipv6(lua_State* L) {
    /* Creates an Address Object representing an IPv6 address. */

#define WSLUA_ARG_Address_ipv6_HOSTNAME 1 /* The address or name of the IP host. */
    Address addr = (Address)g_malloc(sizeof(address));
    ws_in6_addr ip_addr;
    const char* name = luaL_checkstring(L,WSLUA_ARG_Address_ipv6_HOSTNAME);

    if (!get_host_ipaddr6(name, &ip_addr)) {
        memset(&ip_addr, 0, sizeof(ip_addr));
    }

    alloc_address_wmem(NULL, addr, AT_IPv6, sizeof(ip_addr.bytes), &ip_addr.bytes);
    pushAddress(L,addr);
    WSLUA_RETURN(1); /* The Address object */
}

WSLUA_CONSTRUCTOR Address_ether(lua_State *L) {
    /* Creates an Address Object representing an Ethernet address. */

#define WSLUA_ARG_Address_ether_ETH 1 /* The Ethernet address. */
    Address addr = (Address)g_malloc(sizeof(address));
    const char *name = luaL_checkstring(L, WSLUA_ARG_Address_ether_ETH);
    uint8_t eth_buf[6];

    if(!str_to_eth(name, eth_buf))
        memset(eth_buf, 0, sizeof(eth_buf));

    alloc_address_wmem(NULL, addr, AT_ETHER, sizeof(eth_buf), eth_buf);
    pushAddress(L, addr);
    WSLUA_RETURN(1); /* The Address object. */
}

#if 0
/* TODO */
static int Address_ss7(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_sna(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_atalk(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_vines(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_osi(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_arcnet(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_fc(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_string(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_eui64(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_uri(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
static int Address_tipc(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    /* alloc_address() */

    pushAddress(L,addr);
    return 1;
}
#endif

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

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Address__gc(lua_State* L) {
    Address addr = toAddress(L,1);

    if (addr) {
        free_address(addr);
        g_free(addr);
    }

    return 0;
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
    WSLUA_REGISTER_CLASS(Address);
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
