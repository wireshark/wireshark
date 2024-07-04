/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h323.h                                                              */
/* asn2wrs.py -q -L -p h323 -c ./h323.cnf -s ./packet-h323-template -D . -O ../.. RAS-PROTOCOL-TUNNEL.asn ROBUSTNESS-DATA.asn */

/* packet-h323.h
 * Routines for H.235 packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H323_H
#define PACKET_H323_H

/* Generic Extensible Framework */

#define GEF_CTX_SIGNATURE 0x47454658  /* "GEFX" */

typedef struct _gef_ctx_t {
  uint32_t signature;
  struct _gef_ctx_t *parent;
  /*
    H323-MESSAGES
      FeatureDescriptor/<id>
        <id>
      GenericData/<id>
        <id>
    MULTIMEDIA-SYSTEM-CONTROL
      GenericInformation/<id>[-<subid>]
        <id>
      GenericMessage/<id>[-<subid>]
        <id>
      GenericCapability/<id>
        collapsing/<id>
        nonCollapsing/<id>
        nonCollapsingRaw
      EncryptionSync
        <id>
  */
  const char *type;
  const char *id;
  const char *subid;
  const char *key;
} gef_ctx_t;

extern gef_ctx_t* gef_ctx_alloc(wmem_allocator_t *pool, gef_ctx_t *parent, const char *type);
extern bool gef_ctx_check_signature(gef_ctx_t *gefx);
extern gef_ctx_t* gef_ctx_get(void *ptr);
extern void gef_ctx_update_key(wmem_allocator_t *pool, gef_ctx_t *gefx);

#endif  /* PACKET_H323_H */

