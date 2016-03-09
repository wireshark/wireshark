/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ansi_tcap.h                                                         */
/* asn2wrs.py -b -p ansi_tcap -c ./ansi_tcap.cnf -s ./packet-ansi_tcap-template -D . -O ../.. TCAP-Remote-Operations-Information-Objects.asn TCAPPackage.asn */

/* Input file: packet-ansi_tcap-template.h */

#line 1 "./asn1/ansi_tcap/packet-ansi_tcap-template.h"
/* packet-ansi_tcap.h
 *
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
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


#ifndef PACKET_ANSI_TCAP_H
#define PACKET_ANSI_TCAP_H

#define ANSI_TCAP_CTX_SIGNATURE 0x41544341  /* "ATCA" */

struct ansi_tcap_private_t {
  guint32 signature;
  gboolean oid_is_present; /* Is the Application Context Version present */
  const void * objectApplicationId_oid;
  guint32 session_id;
  void * context;
  gchar *TransactionID_str;
  struct {  /* "dynamic" data */
    gint pdu;
      /*
         1 : invoke,
         2 : returnResult,
         3 : returnError,
         4 : reject
      */
    gint OperationCode;
      /*
         0 : national,
         1 : private
      */
    gint32 OperationCode_national;
    gint32 OperationCode_private;
    proto_item *OperationCode_item;
  } d;

};

/*extern void add_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector);*/


/*extern void delete_ansi_tcap_subdissector(guint32 ssn, dissector_handle_t dissector);*/


#endif  /* PACKET_ANSI_TCAP_H */
