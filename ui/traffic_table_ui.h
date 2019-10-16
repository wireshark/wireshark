/* traffic_table_ui.h
 * Helper routines common to conversation/endpoint tables.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TRAFFIC_TABLE_UI_H__
#define __TRAFFIC_TABLE_UI_H__

#ifdef HAVE_MAXMINDDB
#include <stdio.h>

#include "epan/maxmind_db.h"
#include <epan/conversation_table.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Conversation and endpoint lists.
 */

typedef enum {
    CONV_COLUMN_SRC_ADDR,
    CONV_COLUMN_SRC_PORT,
    CONV_COLUMN_DST_ADDR,
    CONV_COLUMN_DST_PORT,
    CONV_COLUMN_PACKETS,
    CONV_COLUMN_BYTES,
    CONV_COLUMN_PKT_AB,
    CONV_COLUMN_BYTES_AB,
    CONV_COLUMN_PKT_BA,
    CONV_COLUMN_BYTES_BA,
    CONV_COLUMN_START,
    CONV_COLUMN_DURATION,
    CONV_COLUMN_BPS_AB,
    CONV_COLUMN_BPS_BA,
    CONV_NUM_COLUMNS,
    CONV_INDEX_COLUMN = CONV_NUM_COLUMNS
} conversation_column_type_e;

extern const char *conv_column_titles[CONV_NUM_COLUMNS];
extern const char *conv_conn_a_title;
extern const char *conv_conn_b_title;
extern const char *conv_abs_start_title;

typedef enum
{
    ENDP_COLUMN_ADDR,
    ENDP_COLUMN_PORT,
    ENDP_COLUMN_PACKETS,
    ENDP_COLUMN_BYTES,
    ENDP_COLUMN_PKT_AB,
    ENDP_COLUMN_BYTES_AB,
    ENDP_COLUMN_PKT_BA,
    ENDP_COLUMN_BYTES_BA,
    ENDP_NUM_COLUMNS,
    ENDP_COLUMN_GEO_COUNTRY = ENDP_NUM_COLUMNS,
    ENDP_COLUMN_GEO_CITY,
    ENDP_COLUMN_GEO_AS_NUM,
    ENDP_COLUMN_GEO_AS_ORG,
    ENDP_NUM_GEO_COLUMNS
} endpoint_column_type_e;

extern const char *endp_column_titles[ENDP_NUM_GEO_COLUMNS];

extern const char *endp_conn_title;

#ifdef HAVE_MAXMINDDB
/**
 * Writes an HTML file containing a map showing the geographical locations
 * of IPv4 and IPv6 addresses.
 *
 * @param [in] fp File handle for writing the HTML file.
 * @param [in] json_only Write GeoJSON data only.
 * @param [in] hosts A NULL-terminated array of 'hostlist_talker_t'. A MMDB
 * lookup should have been completed before for these addresses.
 * @param [in,out] err_str Set to error string on failure. Error string must
 * be g_freed. May be NULL.
 * @return Whether the map file was successfully written with non-empty data.
 */
gboolean write_endpoint_geoip_map(FILE *fp, gboolean json_only, hostlist_talker_t *const *hosts, gchar **err_str);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TRAFFIC_TABLE_UI_H__ */

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
