/** @file
 * Routines for handling DVB-SI character tables (as defined in EN 300 468)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "ws_symbol_export.h"

#include <epan/proto.h>
#include <epan/to_str.h>
#include <epan/tvbuff.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Character encoding types for DVB Service Information (DVB-SI) text fields.
 */
typedef enum {
    DVB_ENCODING_INVALID  = -3, /**< Encoding could not be determined due to an invalid length */
    DVB_ENCODING_RESERVED = -2, /**< Encoding byte is reserved by the DVB-SI specification */
    DVB_ENCODING_UNKNOWN  = -1, /**< Encoding byte is not defined by the DVB-SI specification */

    DVB_ENCODING_LATIN        = 0,  /**< Default Latin character table (DVB default encoding) */
    /* These enumerator values do not have to match the prefix byte values
       from the DVB-SI specification. */
    DVB_ENCODING_ISO_8859_1,        /**< ISO/IEC 8859-1: Latin-1 (Western European) */
    DVB_ENCODING_ISO_8859_2,        /**< ISO/IEC 8859-2: Latin-2 (Central European) */
    DVB_ENCODING_ISO_8859_3,        /**< ISO/IEC 8859-3: Latin-3 (South European) */
    DVB_ENCODING_ISO_8859_4,        /**< ISO/IEC 8859-4: Latin-4 (North European) */
    DVB_ENCODING_ISO_8859_5,        /**< ISO/IEC 8859-5: Latin/Cyrillic */
    DVB_ENCODING_ISO_8859_6,        /**< ISO/IEC 8859-6: Latin/Arabic */
    DVB_ENCODING_ISO_8859_7,        /**< ISO/IEC 8859-7: Latin/Greek */
    DVB_ENCODING_ISO_8859_8,        /**< ISO/IEC 8859-8: Latin/Hebrew */
    DVB_ENCODING_ISO_8859_9,        /**< ISO/IEC 8859-9: Latin-5 (Turkish) */
    DVB_ENCODING_ISO_8859_10,       /**< ISO/IEC 8859-10: Latin-6 (Nordic) */
    DVB_ENCODING_ISO_8859_11,       /**< ISO/IEC 8859-11: Latin/Thai */
    DVB_ENCODING_ISO_8859_13,       /**< ISO/IEC 8859-13: Latin-7 (Baltic Rim) */
    DVB_ENCODING_ISO_8859_14,       /**< ISO/IEC 8859-14: Latin-8 (Celtic) */
    DVB_ENCODING_ISO_8859_15,       /**< ISO/IEC 8859-15: Latin-9 (Western European with Euro sign) */

    DVB_ENCODING_ISO_10646_BMP,     /**< ISO/IEC 10646 Basic Multilingual Plane (UCS-2 / UTF-16 BMP) */
    DVB_ENCODING_KSX_1001,          /**< KS X 1001: Korean national standard character set */
    DVB_ENCODING_GB_2312,           /**< GB 2312: Simplified Chinese national standard character set */
    DVB_ENCODING_ISO_10646_BIG5,    /**< ISO/IEC 10646 encoded via Big5 (Traditional Chinese) */
    DVB_ENCODING_ISO_10646_UTF8_BMP /**< ISO/IEC 10646 BMP encoded as UTF-8 */
} dvb_encoding_e;

/**
 * @brief Analyzes the character set of a DVB string.
 *
 * Determines the encoding of a DVB string based on its first byte and length.
 *
 * @param tvb The TVB buffer containing the DVB data.
 * @param offset The starting offset within the TVB buffer.
 * @param length The length of the DVB string to analyze.
 * @param encoding Pointer to store the detected encoding.
 * @return Number of bytes processed or 1 if invalid.
 */
WS_DLL_PUBLIC
unsigned dvb_analyze_string_charset(tvbuff_t *tvb, int offset, int length,
      dvb_encoding_e *encoding);

/**
 * @brief Convert DVB encoding to item encoding.
 *
 * @param encoding The DVB encoding to convert.
 * @return The corresponding item encoding.
 */
WS_DLL_PUBLIC
unsigned dvb_enc_to_item_enc(dvb_encoding_e encoding);

/**
 * @brief Adds a character table to the protocol tree.
 *
 * This function adds a character table to the protocol tree based on the provided parameters.
 *
 * @param tree The protocol tree to which the character table will be added.
 * @param hf The field ID for the character table.
 * @param tvb The TV buffer containing the data.
 * @param offset The offset within the TV buffer where the data starts.
 * @param length The length of the data in the TV buffer.
 * @param encoding The encoding type of the character table.
 */
WS_DLL_PUBLIC
void dvb_add_chartbl(proto_tree *tree, int hf,
        tvbuff_t *tvb, int offset, int length,
        dvb_encoding_e  encoding);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
