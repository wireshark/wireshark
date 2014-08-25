/* Do not modify this file. Changes will be overwritten */
/* Generated Automatically                              */
/* packet-skinny.h                                      */

/* packet-skinny.h
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 *
 * Author: Diederik de Groot <ddegroot@user.sf.net>, Copyright 2014
 * Rewritten to support newer skinny protocolversions (V0-V22)
 * Based on previous versions/contributions:
 *  - Joerg Mayer <jmayer@loplof.de>, Copyright 2001
 *  - Paul E. Erkkila (pee@erkkila.org) - fleshed out the decode
 *    skeleton to report values for most message/message fields.
 *    Much help from Guy Harris on figuring out the wireshark api.
 *  - packet-aim.c by Ralf Hoelzer <ralf@well.com>, Copyright 2000
 *  - Wireshark - Network traffic analyzer,
 *    By Gerald Combs <gerald@wireshark.org>, Copyright 1998
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

/*
 * Generated Automatically Using (from wireshark base directory):
 *   cog.py -D xmlfile=tools/SkinnyProtocolOptimized.xml -d -c -o epan/dissectors/packet-skinny.c epan/dissectors/packet-skinny.c.in
 */

/* Container for tapping relevant data */
typedef struct _skinny_info_t
{
	guint32 messId;
	guint32 maxProtocolVersion;
	guint32 lineId;
	guint32 callId;
	guint32 passThruId;
	const gchar *messageName;
	guint32 callState;
	gchar *callingParty;
	gchar *calledParty;
	gboolean hasCallInfo;
	guint openreceiveStatus;
	guint startmediatransmisionStatus;
} skinny_info_t;

