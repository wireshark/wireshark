/* cfilter_combo_utils.h
 * Capture filter combo box routines
 *
 * $Id: cfilter_combo_utils.h 12115 2004-09-27 22:55:15Z guy $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

extern void cfilter_combo_recent_write_all(FILE *rf);
extern gboolean cfilter_combo_add_recent(gchar *s);
/** Check the syntax of a capture filter string. This is done by calling pcap_open_live().
 *
 * @param interface_name The interface name to be opened by pcap_open_live().
 * @param filter_str The filter string to be verified.
 */
extern gboolean check_capture_filter_syntax(gchar *interface_name, gchar *filter_str);

#define E_CFILTER_CM_KEY          "capture_filter_combo"
#define E_CFILTER_FL_KEY          "capture_filter_list"
#define RECENT_KEY_CAPTURE_FILTER "recent.capture_filter"