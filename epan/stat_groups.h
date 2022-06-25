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
 *
 * NOTE: the enum below is parsed by epan/wslua/make-init-lua.py in order
 * to generate usable values for Lua scripts to use, so they can add to
 * the menus in the GUI. The perl script's regex is such that the following
 * prefixes must only appear once in this list:
 * REGISTER_ANALYZE_GROUP_CONVERSATION
 * REGISTER_STAT_GROUP_CONVERSATION
 * REGISTER_STAT_GROUP_RESPONSE
 * REGISTER_STAT_GROUP_ENDPOINT
 * In other words, because there is a REGISTER_STAT_GROUP_RESPONSE_TIME, you cannot
 * add a REGISTER_STAT_GROUP_RESPONSE nor a REGISTER_STAT_GROUP_RESPONSE_FOOBAR
 * because they use the same "REGISTER_STAT_GROUP_RESPONSE" prefix.
 * Also, do NOT change the names in the enum - you can add, but not remove.
 * If you do, legacy scripts will break. (which is why the perl script regex isn't better)
 */

/*! Statistics groups. Used for UI menu layout. */
/* This is parsed by make-init-lua.py, so we can't do anything fancy here. */
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
