/* packet-enip.h
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Conversation data support for CIP
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
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

typedef struct {
   guint32 req_num, rep_num;
   nstime_t req_time;
   void *cip_info;
} enip_request_info_t;

void enip_open_cip_connection( packet_info *pinfo,
                               guint16 ConnSerialNumber, guint16 VendorID, guint32 DeviceSerialNumber,
                               guint32 O2TConnID, guint32 T2OConnID );
void enip_close_cip_connection( packet_info *pinfo,
                                guint16 ConnSerialNumber, guint16 VendorID, guint32 DeviceSerialNumber );
