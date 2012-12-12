/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-pres.h                                                              */
/* ../../tools/asn2wrs.py -b -p pres -c ./pres.cnf -s ./packet-pres-template -D . -O ../../epan/dissectors ISO8823-PRESENTATION.asn ISO9576-PRESENTATION.asn */

/* Input file: packet-pres-template.h */

#line 1 "../../asn1/pres/packet-pres-template.h"
/* packet-pres.h
 * Routines for pres packet dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_PRES_H
#define PACKET_PRES_H

/*#include "packet-pres-exp.h"*/

extern char *find_oid_by_pres_ctx_id(packet_info *pinfo, guint32 idx);

#endif  /* PACKET_PRES_H */
