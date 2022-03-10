/* conversations.h
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/

#define MAX_N_CONV_FILTERS 16

is_filter_valid_func fv_func[MAX_N_CONV_FILTERS];
build_filter_string_func bfs_func[MAX_N_CONV_FILTERS];

#define DECLARE_CONV_FLT_FUNCS(N) static gboolean conv_filter_valid_##N(packet_info *pinfo) { \
    gboolean is_right_proto = proto_is_frame_protocol(pinfo->layers, conv_fld_infos[N].proto_name); \
    if (is_right_proto == FALSE) { \
        return FALSE; \
    } \
    char* bi = p_get_proto_data(pinfo->pool, pinfo, proto_falco_bridge, PROTO_DATA_CONVINFO_USER_##N); \
    if (bi == NULL) { \
        return FALSE; \
    } \
    return TRUE; \
} \
static gchar* \
conv_filter_build_##N(packet_info *pinfo) { \
    char* bi = p_get_proto_data(pinfo->pool, pinfo, proto_falco_bridge, PROTO_DATA_CONVINFO_USER_##N); \
    const char* fname = conv_fld_infos[N].field_info->hfinfo.abbrev; \
    return g_strdup_printf("%s eq \"%s\"", fname, bi); \
}

#define MAP_CONV_FLT_FUNCS(N) fv_func[N] = conv_filter_valid_##N; \
bfs_func[N] = conv_filter_build_##N;

#define DECLARE_CONV_FLTS() DECLARE_CONV_FLT_FUNCS(0) \
DECLARE_CONV_FLT_FUNCS(1) \
DECLARE_CONV_FLT_FUNCS(2) \
DECLARE_CONV_FLT_FUNCS(3) \
DECLARE_CONV_FLT_FUNCS(4) \
DECLARE_CONV_FLT_FUNCS(5) \
DECLARE_CONV_FLT_FUNCS(6) \
DECLARE_CONV_FLT_FUNCS(7) \
DECLARE_CONV_FLT_FUNCS(8) \
DECLARE_CONV_FLT_FUNCS(9) \
DECLARE_CONV_FLT_FUNCS(10) \
DECLARE_CONV_FLT_FUNCS(11) \
DECLARE_CONV_FLT_FUNCS(12) \
DECLARE_CONV_FLT_FUNCS(13) \
DECLARE_CONV_FLT_FUNCS(14) \
DECLARE_CONV_FLT_FUNCS(15)

#define MAP_CONV_FLTS() MAP_CONV_FLT_FUNCS(0) \
MAP_CONV_FLT_FUNCS(1) \
MAP_CONV_FLT_FUNCS(2) \
MAP_CONV_FLT_FUNCS(3) \
MAP_CONV_FLT_FUNCS(4) \
MAP_CONV_FLT_FUNCS(5) \
MAP_CONV_FLT_FUNCS(6) \
MAP_CONV_FLT_FUNCS(7) \
MAP_CONV_FLT_FUNCS(8) \
MAP_CONV_FLT_FUNCS(9) \
MAP_CONV_FLT_FUNCS(10) \
MAP_CONV_FLT_FUNCS(11) \
MAP_CONV_FLT_FUNCS(12) \
MAP_CONV_FLT_FUNCS(13) \
MAP_CONV_FLT_FUNCS(14) \
MAP_CONV_FLT_FUNCS(15)
