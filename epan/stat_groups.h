/* stat_groups.h
 * Definitions of groups for statistics
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
 * NOTE: the enum below is parsed by epan/wslua/make-init-lua.pl in order
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

/** The group this stat should be registered in. */
typedef enum {
    REGISTER_ANALYZE_GROUP_UNSORTED,            /* unsorted analyze stuff */
    REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER, /* conversation filters. Unused? */
    REGISTER_STAT_GROUP_UNSORTED,               /* unsorted statistic function */
    REGISTER_STAT_GROUP_GENERIC,                /* generic statistic function, not specific to a protocol */
    REGISTER_STAT_GROUP_CONVERSATION_LIST,      /* member of the conversation list */
    REGISTER_STAT_GROUP_ENDPOINT_LIST,          /* member of the endpoint list */
    REGISTER_STAT_GROUP_RESPONSE_TIME,          /* member of the service response time list */
    REGISTER_STAT_GROUP_TELEPHONY,              /* telephony specific */
    REGISTER_STAT_GROUP_TELEPHONY_ANSI,         /* name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_GSM,          /* GSM (and UMTS?) */
    REGISTER_STAT_GROUP_TELEPHONY_LTE,          /* name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_MTP3,         /* name says it all */
    REGISTER_STAT_GROUP_TELEPHONY_SCTP,         /* name says it all */
    REGISTER_TOOLS_GROUP_UNSORTED               /* unsorted tools */
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
