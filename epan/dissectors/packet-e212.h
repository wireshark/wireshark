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

#include <epan/value_string.h>
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
    E212_NRCGI
} e212_number_type_t;

gchar* dissect_e212_mcc_mnc_wmem_packet_str(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, e212_number_type_t number_type, gboolean little_endian);

WS_DLL_PUBLIC
int dissect_e212_mcc_mnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, e212_number_type_t number_type, gboolean little_endian);

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
 * A wmem allocated string will be returned.
 */
WS_DLL_PUBLIC
const gchar * dissect_e212_imsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length, gboolean skip_first);

/**
 *
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset, fetch UTF8-encoded digits from the tvbuff and then
 * create a string in the tree and a corresponding filter.
 *
 * The wmem allocated string will be returned.
 */
WS_DLL_PUBLIC
const gchar * dissect_e212_utf8_imsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length);

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
