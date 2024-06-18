/* ipaddr.c
 *
 * Copyright 2023, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_BUILD_DLL
#include <wireshark.h>
#include <wsutil/plugins.h>
#include <epan/dfilter/dfilter-plugin.h>
#include <epan/iana-ip.h>

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

typedef bool (*ip_is_func_t)(fvalue_t *);

static const struct ws_iana_ip_special_block *
lookup_block(fvalue_t *fv)
{
    switch (fvalue_type_ftenum(fv)) {
        case FT_IPv4:
            return ws_iana_ipv4_special_block_lookup(fvalue_get_ipv4(fv)->addr);
        case FT_IPv6:
            return ws_iana_ipv6_special_block_lookup(&fvalue_get_ipv6(fv)->addr);
        default:
            break;
    }
    ws_assert_not_reached();
}

static bool
df_func_ip_special_name(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    GPtrArray *arg;
    fvalue_t *fv_res;
    const struct ws_iana_ip_special_block *ptr;

    ws_assert(arg_count == 1);
    arg = stack->data;
    if (arg == NULL)
        return false;

    for (unsigned i = 0; i < arg->len; i++) {
        ptr = lookup_block(arg->pdata[i]);
        if (ptr == NULL)
            continue;
        fv_res = fvalue_new(FT_STRING);
        fvalue_set_string(fv_res, ptr->name);
        df_cell_append(retval, fv_res);
    }

    return !df_cell_is_empty(retval);
}

static bool
df_func_ip_special_mask(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    GPtrArray *arg;
    fvalue_t *fv_res;
    const struct ws_iana_ip_special_block *ptr;
    uint32_t mask;

    ws_assert(arg_count == 1);
    arg = stack->data;
    if (arg == NULL)
        return false;

    for (unsigned i = 0; i < arg->len; i++) {
        ptr = lookup_block(arg->pdata[i]);
        if (ptr == NULL)
            continue;
        mask = 0;
        if (ptr->reserved > 0)
            mask |= (1UL << 0);
        if (ptr->global > 0)
            mask |= (1UL << 1);
        if (ptr->forwardable > 0)
            mask |= (1UL << 2);
        if (ptr->destination > 0)
            mask |= (1UL << 3);
        if (ptr->source > 0)
            mask |= (1UL << 4);
        fv_res = fvalue_new(FT_UINT32);
        fvalue_set_uinteger(fv_res, mask);
        df_cell_append(retval, fv_res);
    }

    return !df_cell_is_empty(retval);
}

static bool
ip_is_link_local(fvalue_t *fv)
{
    switch (fvalue_type_ftenum(fv)) {
        case FT_IPv4:
            return in4_addr_is_link_local(fvalue_get_ipv4(fv)->addr);
        case FT_IPv6:
            return in6_addr_is_linklocal(&fvalue_get_ipv6(fv)->addr);
        default:
            break;
    }
    ws_assert_not_reached();
}

static bool
ip_is_multicast(fvalue_t *fv)
{
    switch (fvalue_type_ftenum(fv)) {
        case FT_IPv4:
            return in4_addr_is_multicast(fvalue_get_ipv4(fv)->addr);
        case FT_IPv6:
            return in6_addr_is_multicast(&fvalue_get_ipv6(fv)->addr);
        default:
            break;
    }
    ws_assert_not_reached();
}

static bool
ipv4_is_rfc1918(fvalue_t *fv)
{
    switch (fvalue_type_ftenum(fv)) {
        case FT_IPv4:
            return in4_addr_is_private(fvalue_get_ipv4(fv)->addr);
        case FT_IPv6:
            return false;
        default:
            break;
    }
    ws_assert_not_reached();

}

static bool
ipv6_is_ula(fvalue_t *fv)
{
    switch (fvalue_type_ftenum(fv)) {
        case FT_IPv4:
            return false;
        case FT_IPv6:
            return in6_addr_is_uniquelocal(&fvalue_get_ipv6(fv)->addr);
        default:
            break;
    }
    ws_assert_not_reached();
}

static bool
df_func_ip_is_any(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval, ip_is_func_t is_func)
{
    GPtrArray *arg;
    fvalue_t *fv_res;

    ws_assert(arg_count == 1);
    arg = stack->data;
    if (arg == NULL)
        return false;

    for (unsigned i = 0; i < arg->len; i++) {
        fv_res = fvalue_new(FT_BOOLEAN);
        fvalue_set_uinteger64(fv_res, is_func(arg->pdata[i]));
        df_cell_append(retval, fv_res);
    }

    return !df_cell_is_empty(retval);
}

static bool
df_func_ip_is_link_local(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_ip_is_any(stack, arg_count, retval, ip_is_link_local);
}

static bool
df_func_ip_is_multicast(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_ip_is_any(stack, arg_count, retval, ip_is_multicast);
}

static bool
df_func_ip_is_rfc1918(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_ip_is_any(stack, arg_count, retval, ipv4_is_rfc1918);
}

static bool
df_func_ip_is_ula(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_ip_is_any(stack, arg_count, retval, ipv6_is_ula);
}

#define IPv4 1
#define IPv6 2
#define Both 3

static bool
check_which(ftenum_t ftype, int which)
{
    switch (which) {
        case IPv4: return ftype == FT_IPv4;
        case IPv6: return ftype == FT_IPv6;
        case Both: return ftype == FT_IPv4 || ftype == FT_IPv6;
        default:
            break;
    }
    ws_assert_not_reached();
}

static const char *
print_which(int which)
{
    switch (which) {
        case IPv4: return "IPv4";
        case IPv6: return "IPv6";
        case Both: return "IPv4/IPv6";
        default:
            break;
    }
    ws_assert_not_reached();
}

static void
check_ip_field(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            GSList *param_list, df_loc_t func_loc, int which)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;
    ftenum_t ftype;

    if (stnode_type_id(param) == STTYPE_FIELD) {
        ftype = df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);
        if (check_which(ftype, which)) {
            return;
        }
    }
    dfunc_fail(dfw, param, "Only %s fields can be used as parameter for %s()",
                                print_which(which), func_name);
}

static ftenum_t
semcheck_ip_special_name(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            GSList *param_list, df_loc_t func_loc)
{
    check_ip_field(dfw, func_name, logical_ftype, param_list, func_loc, Both);
    return FT_STRING;
}

static ftenum_t
semcheck_ip_special_mask(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            GSList *param_list, df_loc_t func_loc)
{
    check_ip_field(dfw, func_name, logical_ftype, param_list, func_loc, Both);
    return FT_UINT32;
}

static ftenum_t
semcheck_is_ip_field(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            GSList *param_list, df_loc_t func_loc)
{
    check_ip_field(dfw, func_name, logical_ftype, param_list, func_loc, Both);
    return FT_BOOLEAN;
}

static df_func_def_t func_ip_special_name = {
    "ip_special_name",
    df_func_ip_special_name,
    1, 1,
    FT_STRING,
    semcheck_ip_special_name,
};

static df_func_def_t func_ip_special_mask = {
    "ip_special_mask",
    df_func_ip_special_mask,
    1, 1,
    FT_UINT32,
    semcheck_ip_special_mask,
};

static df_func_def_t func_ip_is_link_local = {
    "ip_linklocal",
    df_func_ip_is_link_local,
    1, 1,
    FT_BOOLEAN,
    semcheck_is_ip_field,
};

static df_func_def_t func_ip_is_multicast = {
    "ip_multicast",
    df_func_ip_is_multicast,
    1, 1,
    FT_BOOLEAN,
    semcheck_is_ip_field,
};

static df_func_def_t func_ip_is_rfc1918 = {
    "ip_rfc1918",
    df_func_ip_is_rfc1918,
    1, 1,
    FT_BOOLEAN,
    semcheck_is_ip_field,
};

static df_func_def_t func_ip_is_ula = {
    "ip_ula",
    df_func_ip_is_ula,
    1, 1,
    FT_BOOLEAN,
    semcheck_is_ip_field,
};

static void
init(void)
{
    df_func_register(&func_ip_special_name);
    df_func_register(&func_ip_special_mask);
    df_func_register(&func_ip_is_link_local);
    df_func_register(&func_ip_is_multicast);
    df_func_register(&func_ip_is_rfc1918);
    df_func_register(&func_ip_is_ula);
}

static void
cleanup(void)
{
    df_func_deregister(&func_ip_special_name);
    df_func_deregister(&func_ip_special_mask);
    df_func_deregister(&func_ip_is_link_local);
    df_func_deregister(&func_ip_is_multicast);
    df_func_deregister(&func_ip_is_rfc1918);
    df_func_deregister(&func_ip_is_ula);
}

void
plugin_register(void)
{
    static dfilter_plugin plug;

    plug.init = init;
    plug.cleanup = cleanup;
    dfilter_plugins_register(&plug);
}

uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DFILTER;
}
