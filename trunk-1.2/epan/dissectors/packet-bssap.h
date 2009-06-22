/* packet-bssap.h
 * Routines for Base Station Subsystem Application Part (BSSAP/BSAP) dissection
 * Specifications from 3GPP2 (www.3gpp2.org) and 3GPP (www.3gpp.org)
 *	IOS 4.0.1 (BSAP)
 *	GSM 08.06 (BSSAP)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define BSSAP_PDU_TYPE_BSSMAP	0x00
#define BSSAP_PDU_TYPE_DTAP	0x01

#define BSSAP_PDU_TYPE_BSMAP	BSSAP_PDU_TYPE_BSSMAP
