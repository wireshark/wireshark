/* tshark-tap.h
 * Registation tap hooks for TShark
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __TSHARK_TAP_H__
#define __TSHARK_TAP_H__

#include <epan/conversation_table.h>

extern void init_iousers(struct register_ct* ct, const char *filter);
extern void init_hostlists(struct register_ct* ct, const char *filter);
extern gboolean register_srt_tables(const void *key, void *value, void *userdata);
extern gboolean register_rtd_tables(const void *key, void *value, void *userdata);
extern gboolean register_simple_stat_tables(const void *key, void *value, void *userdata);

#endif /* __TSHARK_TAP_H__ */
