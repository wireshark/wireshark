/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-camel.h                                                             */
/* ../../tools/asn2wrs.py -b -L -p camel -c ./camel.cnf -s ./packet-camel-template -D . -O ../../epan/dissectors CAP-object-identifiers.asn CAP-classes.asn CAP-datatypes.asn CAP-errorcodes.asn CAP-errortypes.asn CAP-operationcodes.asn CAP-GPRS-ReferenceNumber.asn CAP-gsmSCF-gsmSRF-ops-args.asn CAP-gsmSSF-gsmSCF-ops-args.asn CAP-gprsSSF-gsmSCF-ops-args.asn CAP-SMS-ops-args.asn CAP-U-ABORT-Data.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* Input file: packet-camel-template.h */

#line 1 "../../asn1/camel/packet-camel-template.h"
/* packet-camel-template.h
 * Routines for Camel
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Copyright 2005, Olivier Jacques <olivier.jacques@hp.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */
/* 
 * Indentation logic: this file is indented with 2 spaces indentation. 
 *                    there are no tabs.
 */


#ifndef PACKET_CAMEL_H
#define PACKET_CAMEL_H

void proto_reg_handoff_camel(void);
void proto_register_camel(void);

/* Defines for the camel taps */
#define	camel_MAX_NUM_OPR_CODES	256


WS_VAR_IMPORT const value_string camel_opr_code_strings[];
/* #include "packet-camel-exp.h"*/

#endif  /* PACKET_camel_H */
