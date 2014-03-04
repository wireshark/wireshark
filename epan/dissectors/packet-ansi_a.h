/* packet-ansi_a.h
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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

#include <epan/proto.h>

typedef struct _ansi_a_tap_rec_t {
    /*
     * value from packet-bssap.h
     */
    guint8              pdu_type;
    guint8              message_type;
} ansi_a_tap_rec_t;

typedef struct ext_value_string_t
{
    guint32             value;
    const gchar         *strptr;
    gint                dec_index;
}
ext_value_string_t;


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
WS_DLL_PUBLIC const ext_value_string_t *ansi_a_bsmap_strings;
WS_DLL_PUBLIC const ext_value_string_t *ansi_a_dtap_strings;
WS_DLL_PUBLIC const ext_value_string_t ansi_a_ios501_bsmap_strings[];
WS_DLL_PUBLIC const ext_value_string_t ansi_a_ios501_dtap_strings[];
WS_DLL_PUBLIC const ext_value_string_t ansi_a_ios401_bsmap_strings[];
WS_DLL_PUBLIC const ext_value_string_t ansi_a_ios401_dtap_strings[];

/*
 * Not strictly A-interface info, but put here to avoid file polution
 *
 * Title                3GPP2                   Other
 *
 *   Administration of Parameter Value Assignments for
 *   cdma2000 Spread Spectrum Standards
 *                      3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
 */
WS_DLL_PUBLIC const value_string ansi_tsb58_encoding_vals[];
WS_DLL_PUBLIC const value_string ansi_tsb58_srvc_cat_vals[];
WS_DLL_PUBLIC value_string_ext ansi_tsb58_srvc_cat_vals_ext;
WS_DLL_PUBLIC const value_string ansi_tsb58_language_ind_vals[];
WS_DLL_PUBLIC value_string_ext ansi_tsb58_language_ind_vals_ext;

#define ANSI_TSB58_SRVC_CAT_CMAS_MIN    0x1000
#define ANSI_TSB58_SRVC_CAT_CMAS_MAX    0x1004

/*
 * Title                3GPP2                   Other
 *
 *                      3GPP2 C.S0005
 */
WS_DLL_PUBLIC const value_string ansi_a_ms_info_rec_num_type_vals[];
WS_DLL_PUBLIC const value_string ansi_a_ms_info_rec_num_plan_vals[];
/*
 * END Not strictly A-interface info
 */

#define A_VARIANT_IS634         4
#define A_VARIANT_TSB80         5
#define A_VARIANT_IS634A        6
#define A_VARIANT_IOS2          7
#define A_VARIANT_IOS3          8
#define A_VARIANT_IOS401        9
#define A_VARIANT_IOS501        10

WS_DLL_PUBLIC gint a_global_variant;

/*
 * allows ANSI MAP to use this for IS-880 enhancements
 * based on the 'ansi_a_ios401_elem_1_strings/ansi_a_ios501_elem_1_strings'
 */
WS_DLL_PUBLIC const ext_value_string_t *ansi_a_elem_1_strings;

/*
 * maximum number of strings that are allowed
 * 255 because IEI are 1 octet in length
 *
 * this define is required by dissectors that need to
 * size based on the 'ansi_a_elem_1_strings'
 * array
 */
#define ANSI_A_MAX_NUM_IOS_ELEM_1_STRINGS       255

void dissect_cdma2000_a1_elements(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint len);

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
