/* packet-e212.h
 * E212 tables
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_E212_H__
#define __PACKET_E212_H__

#include <wsutil/value_string.h>
#include "ws_symbol_export.h"

extern value_string_ext E212_codes_ext;

extern value_string_ext mcc_mnc_2digits_codes_ext;

extern value_string_ext mcc_mnc_3digits_codes_ext;

typedef enum {
    E212_NONE,
    E212_LAI,
    E212_RAI,
    E212_SAI,
    E212_CGI,
    E212_ECGI,
    E212_TAI,
    E212_NRCGI,
    E212_5GSTAI,
    E212_GUMMEI,
    E212_GUAMI,
    E212_SERV_NET,
} e212_number_type_t;

char* dissect_e212_mcc_mnc_wmem_packet_str(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, e212_number_type_t number_type, bool little_endian);
void add_assoc_imsi_item(tvbuff_t *tvb _U_, proto_tree *tree, const char* imsi_str);

WS_DLL_PUBLIC
int dissect_e212_mcc_mnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, e212_number_type_t number_type, bool little_endian);

WS_DLL_PUBLIC
int dissect_e212_mcc_mnc_in_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

WS_DLL_PUBLIC
int dissect_e212_mcc_mnc_in_utf8_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset);

/**
 *
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset, fetch BCD encoded digits from a tvbuff starting from either
 * the low or high half byte, formatting the digits according to a digit
 * set of 0-9 returning "?" for overdecadic digits and then
 * create a string in the tree and a corresponding filter
 *
 * Note a tvbuff content of 0xf is considered a 'filler' and will end the
 * conversion.
 *
 * When skip_first is true, the high bit of the skipped nibble is treated as a odd/even indicator,
 * according to Figure 10.5.4/3GPP TS 24.008 Mobile Identity information element
 *
 * A wmem allocated string will be returned.
 */
WS_DLL_PUBLIC
const char * dissect_e212_imsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, bool skip_first);

/**
 *
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset, fetch UTF8-encoded digits from the tvbuff and then
 * create a string in the tree and a corresponding filter.
 *
 * The wmem allocated string will be returned.
 */
WS_DLL_PUBLIC
const char * dissect_e212_utf8_imsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length);

#endif /* __PACKET_E212_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
