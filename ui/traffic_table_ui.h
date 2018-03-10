/* traffic_table_ui.h
 * Copied from gtk/conversations_table.h   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#ifndef __CONVERSATION_UI_H__
#define __CONVERSATION_UI_H__

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONVERSATION_UI_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
