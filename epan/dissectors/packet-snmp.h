/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-snmp.h                                                            */
/* ../../tools/asn2eth.py -X -b -e -p snmp -c snmp.cnf -s packet-snmp-template snmp.asn */

/* Input file: packet-snmp-template.h */

#line 1 "packet-snmp-template.h"
/* packet-snmp.h
 * Routines for snmp packet dissection
 *
 * $Id$
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

#ifndef PACKET_SNMP_H
#define PACKET_SNMP_H

/*
 * Guts of the SNMP dissector - exported for use by protocols such as
 * ILMI.
 */
extern guint dissect_snmp_pdu(tvbuff_t *, int, packet_info *, proto_tree *tree,
    int, gint, gboolean);
extern int dissect_snmp_engineid(proto_tree *, tvbuff_t *, int, int);

/*#include "packet-snmp-exp.h"*/

#endif  /* PACKET_SNMP_H */
