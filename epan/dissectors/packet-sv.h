/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-sv.h                                                                */
/* asn2wrs.py -b -p sv -c ./sv.cnf -s ./packet-sv-template -D . -O ../.. sv.asn */

/* Input file: packet-sv-template.h */

#line 1 "./asn1/sv/packet-sv-template.h"
/* packet-sv.h
 * Routines for IEC 61850 Sampled Vales packet dissection
 * Michael Bernhard 2008
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

#ifndef __PACKET_SV_H__
#define __PACKET_SV_H__

#define IEC61850_SV_MAX_PHSMEAS_ENTRIES 20

typedef struct _sv_phs_meas {
	gint32 value;
	guint32 qual;
} sv_phs_meas;

typedef struct _sv_frame_data {
	guint16 smpCnt;
	guint8 smpSynch;
	guint8 num_phsMeas;
	sv_phs_meas phsMeas[IEC61850_SV_MAX_PHSMEAS_ENTRIES];
	guint16 smpMod;
} sv_frame_data;

#endif /*__PACKET_SV_H__*/
