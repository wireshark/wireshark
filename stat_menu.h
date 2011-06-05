/* stat_menu.h
 * Menu definitions for use by stats
 *
 * $Id$
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

#ifndef __STATMENU_H__
#define __STATMENU_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Add a new menu item for a stat.
 */

/*
 * XXX - defines stuff usable regardless of the GUI toolkit.  Right now,
 * that's only the menu group, which is used by tap_param_dlg.h.
 *
 * XXX - stats should be able to register additional menu groups, although
 * the question then would be "in what order should they appear in the menu?"
 */

/** The menu group this stat should be registered in. */
typedef enum {
    REGISTER_ANALYZE_GROUP_UNSORTED,            /* unsorted analyze stuff */
    REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER, /* conversation filters */
    REGISTER_STAT_GROUP_UNSORTED,               /* unsorted statistic function */
    REGISTER_STAT_GROUP_GENERIC,                /* generic statistic function, not specific to a protocol */
    REGISTER_STAT_GROUP_CONVERSATION_LIST,      /* member of the conversation list */
    REGISTER_STAT_GROUP_ENDPOINT_LIST,          /* member of the endpoint list */
    REGISTER_STAT_GROUP_RESPONSE_TIME,          /* member of the service response time list */
    REGISTER_STAT_GROUP_TELEPHONY,              /* telephony specific */
    REGISTER_TOOLS_GROUP_UNSORTED               /* unsorted tools */
} register_stat_group_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STATMENU_H__ */
