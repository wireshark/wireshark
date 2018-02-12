/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ansi_map.h                                                          */
/* asn2wrs.py -b -p ansi_map -c ./ansi_map.cnf -s ./packet-ansi_map-template -D . -O ../.. ansi_map.asn */

/* Input file: packet-ansi_map-template.h */

#line 1 "./asn1/ansi_map/packet-ansi_map-template.h"
/* packet-ansi_map.h
 * Routines for ansi_map packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ANSI_MAP_H
#define PACKET_ANSI_MAP_H

#include "ws_symbol_export.h"

#define	ANSI_MAP_MAX_NUM_MESSAGE_TYPES	256

typedef struct _ansi_map_tap_rec_t {
    guint8		message_type;
    guint16		size;
} ansi_map_tap_rec_t;


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC const value_string ansi_map_opr_code_strings[];



/*#include "packet-ansi_map-exp.h" */

#endif  /* PACKET_ansi_map_H */


