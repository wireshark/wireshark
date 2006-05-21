/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler    */
/* ./packet-mms.h                                                             */
/* ../../tools/asn2eth.py -X -b -e -p mms -c mms.cnf -s packet-mms-template mms.asn */

/* Input file: packet-mms-template.h */

#line 1 "packet-mms-template.h"
/* packet-mms.h
 * Routines for MMS packet dissection
 *   Ronnie Sahlberg 2005
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

#ifndef PACKET_MMS_H
#define PACKET_MMS_H


/*--- Included file: packet-mms-exp.h ---*/
#line 1 "packet-mms-exp.h"
extern const value_string mms_MMSpdu_vals[];
int dissect_mms_MMSpdu(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

/*--- End of included file: packet-mms-exp.h ---*/
#line 30 "packet-mms-template.h"

#endif  /* PACKET_MMS_H */

