/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h323.h                                                              */
/* asn2wrs.py -p h323 -c ./h323.cnf -s ./packet-h323-template -D . -O ../.. RAS-PROTOCOL-TUNNEL.asn ROBUSTNESS-DATA.asn */

/* Input file: packet-h323-template.h */

#line 1 "./asn1/h323/packet-h323-template.h"
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
  guint32 signature;
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
  const gchar *type;
  const gchar *id;
  const gchar *subid;
  const gchar *key;
} gef_ctx_t;

extern gef_ctx_t* gef_ctx_alloc(gef_ctx_t *parent, const gchar *type);
extern gboolean gef_ctx_check_signature(gef_ctx_t *gefx);
extern gef_ctx_t* gef_ctx_get(void *ptr);
extern void gef_ctx_update_key(gef_ctx_t *gefx);

#endif  /* PACKET_H323_H */

