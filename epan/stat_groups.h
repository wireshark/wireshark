/* stat_groups.h
 * Definitions of groups for statistics
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STAT_GROUPS_H__
#define __STAT_GROUPS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Add a new menu item for a stat.
 */

/*
 * Menu statistics group definitions. Used by ui/qt/tap_parameter_dialog.h
 * and ui/gtk/tap_param_dlg.h.
 *
 * XXX - stats should be able to register additional menu groups, although
 * the question then would be "in what order should they appear in the menu?"
 */

/*! Statistics groups. Used for UI menu layout. */
typedef enum register_stat_group_e {
    REGISTER_PACKET_ANALYZE_GROUP_UNSORTED,     /*!< Unsorted packet analysis */
    REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER, /*!< Conversation filters. Unused? */
    REGISTER_PACKET_STAT_GROUP_UNSORTED,        /*!< Unsorted packet statistics */
    REGISTER_STAT_GROUP_GENERIC,                /*!< Generic statistics, not specific to a protocol */
    REGISTER_STAT_GROUP_CONVERSATION_LIST,      /*!< Member of the conversation list */
    REGISTER_STAT_GROUP_ENDPOINT_LIST,          /*!< Member of the endpoint list */
    REGISTER_STAT_GROUP_RESPONSE_TIME,          /*!< Member of the service response time list */
    REGISTER_STAT_GROUP_RSERPOOL,               /*!< Member of the RSerPool list */
    REGISTER_STAT_GROUP_TELEPHONY,              /*!< Telephony specific */
    REGISTER_STAT_GROUP_TELEPHONY_ANSI,         /*!< Name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_GSM,          /*!< GSM (and UMTS?) */
    REGISTER_STAT_GROUP_TELEPHONY_LTE,          /*!< Name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_MTP3,         /*!< Name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_SCTP,         /*!< Name says it all */
    REGISTER_TOOLS_GROUP_UNSORTED,              /*!< Unsorted tools */
    REGISTER_LOG_ANALYZE_GROUP_UNSORTED,        /*!< Unsorted log analysis */
    REGISTER_LOG_STAT_GROUP_UNSORTED,           /*!< Unsorted log statistics */
} register_stat_group_t;

/** Format types for "Save As..." */
/* XXX Is there a more appropriate place to define this? */
typedef enum _st_format_type {
    ST_FORMAT_PLAIN, ST_FORMAT_CSV, ST_FORMAT_XML, ST_FORMAT_YAML
    } st_format_type;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STAT_GROUPS_H__ */
