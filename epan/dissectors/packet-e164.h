/* packet-e164.h
 * E164 tables
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_E164_H__
#define __PACKET_E164_H__

#include <epan/value_string.h>
#include "ws_symbol_export.h"

extern const value_string E164_country_code_value[];
extern const value_string E164_ISO3166_country_code_short_value[];
extern value_string_ext E164_ISO3166_country_code_short_value_ext;
extern const value_string E164_International_Networks_vals[];

#define E164_NA_INTERNATIONAL_NUMBER 4

typedef enum {
	NONE,
	CALLING_PARTY_NUMBER,
	CALLED_PARTY_NUMBER
} e164_number_type_t;

typedef struct {
	e164_number_type_t e164_number_type;
	guint nature_of_address;
	const char *E164_number_str;	/* E164 number string */
	guint E164_number_length;	/* Length of the E164_number string */
} e164_info_t;

typedef enum {
	E164_ENC_BINARY,
	E164_ENC_BCD,
	E164_ENC_UTF8
} e164_encoding_t;

extern void dissect_e164_number(tvbuff_t *tvb, proto_tree *tree, int offset, int length, e164_info_t e164_info);
WS_DLL_PUBLIC void dissect_e164_cc(tvbuff_t *tvb, proto_tree *tree, int offset, e164_encoding_t encoding);
WS_DLL_PUBLIC const gchar * dissect_e164_msisdn(tvbuff_t *tvb, proto_tree *tree, int offset, int length, e164_encoding_t encoding);
#endif
