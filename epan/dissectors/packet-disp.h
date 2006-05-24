/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-disp.h                                                            */
/* ../../tools/asn2wrs.py -b -e -p disp -c disp.cnf -s packet-disp-template disp.asn */

/* Input file: packet-disp-template.h */

#line 1 "packet-disp-template.h"
/* packet-disp.h
 * Routines for X.525 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
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

#ifndef PACKET_DISP_H
#define PACKET_DISP_H


/*--- Included file: packet-disp-exp.h ---*/
#line 1 "packet-disp-exp.h"
int dissect_disp_AgreementID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-disp-exp.h ---*/
#line 30 "packet-disp-template.h"

#endif  /* PACKET_DISP_H */
