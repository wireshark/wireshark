/* packet-skinny.h
 * Routines for skinny packet disassembly
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


/* Container for tapping relevant data */
typedef struct _skinny_info_t
{
	guint32 messId;
	guint32 lineId;
	guint32 callId;
	guint32 passThruId;
	const gchar *messageName;
	guint32 callState;
	gchar *callingParty;
	gchar *calledParty;
	gboolean hasCallInfo;
} skinny_info_t;

