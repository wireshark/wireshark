/* packet-ansi_tcap.h
 *
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_ANSI_TCAP_H
#define PACKET_ANSI_TCAP_H

#define ANSI_TCAP_CTX_SIGNATURE 0x41544341  /* "ATCA" */

struct ansi_tcap_private_t {
  uint32_t signature;
  bool oid_is_present; /* Is the Application Context Version present */
  const void * objectApplicationId_oid;
  uint32_t session_id;
  void * context;
  char *TransactionID_str;
  struct {  /* "dynamic" data */
    int pdu;
      /*
         1 : invoke,
         2 : returnResult,
         3 : returnError,
         4 : reject
      */
    int OperationCode;
      /*
         0 : national,
         1 : private
      */
    int32_t OperationCode_national;
    int32_t OperationCode_private;
    proto_item *OperationCode_item;
  } d;

};

/*extern void add_ansi_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector);*/


/*extern void delete_ansi_tcap_subdissector(uint32_t ssn, dissector_handle_t dissector);*/


#endif  /* PACKET_ANSI_TCAP_H */
