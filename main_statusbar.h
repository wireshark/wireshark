/* main_statusbar.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __MAIN_STATUSBAR_H__
#define __MAIN_STATUSBAR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void profile_bar_update(void);
void packets_bar_update(void);
void status_expert_update(void);

/** Push a formatted message referring to the currently-selected field
 * onto the statusbar.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_field_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/** Pop a message referring to the currently-selected field off the statusbar.
 */
void statusbar_pop_field_msg(void);

/** Push a formatted message referring to the current filter onto the
 * statusbar.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_filter_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

/** Pop a message referring to the current filter off the statusbar.
 */
void statusbar_pop_filter_msg(void);

/** Push a formatted temporary message onto the statusbar. The message
 * is automatically removed at a later interval.
 *
 * @param msg_format The format string for the message
 */
void statusbar_push_temporary_msg(const gchar *msg_format, ...)
    G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MAIN_STATUSBAR_H__ */
