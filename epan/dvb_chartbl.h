/** @file
 * Routines for handling DVB-SI character tables (as defined in EN 300 468)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __DVB_CHARTBL_H__
#define __DVB_CHARTBL_H__

#include "ws_symbol_export.h"

#include <epan/proto.h>
#include <epan/to_str.h>
#include <epan/tvbuff.h>
#include <epan/value_string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    DVB_ENCODING_INVALID   = -3, /* length invalid */
    DVB_ENCODING_RESERVED  = -2, /* reserved by spec */
    DVB_ENCODING_UNKNOWN   = -1,  /* not defined by spec */

    DVB_ENCODING_LATIN = 0,
    /* these defines don't have to match with the values
       from the DVB-SI specification */
    DVB_ENCODING_ISO_8859_1,
    DVB_ENCODING_ISO_8859_2,
    DVB_ENCODING_ISO_8859_3,
    DVB_ENCODING_ISO_8859_4,
    DVB_ENCODING_ISO_8859_5,
    DVB_ENCODING_ISO_8859_6,
    DVB_ENCODING_ISO_8859_7,
    DVB_ENCODING_ISO_8859_8,
    DVB_ENCODING_ISO_8859_9,
    DVB_ENCODING_ISO_8859_10,
    DVB_ENCODING_ISO_8859_11,
    DVB_ENCODING_ISO_8859_13,
    DVB_ENCODING_ISO_8859_14,
    DVB_ENCODING_ISO_8859_15,

    DVB_ENCODING_ISO_10646_BMP,
    DVB_ENCODING_KSX_1001,
    DVB_ENCODING_GB_2312,
    DVB_ENCODING_ISO_10646_BIG5,
    DVB_ENCODING_ISO_10646_UTF8_BMP
} dvb_encoding_e;

WS_DLL_PUBLIC
unsigned dvb_analyze_string_charset(tvbuff_t *tvb, int offset, int length,
      dvb_encoding_e *encoding);

WS_DLL_PUBLIC
unsigned dvb_enc_to_item_enc(dvb_encoding_e encoding);

WS_DLL_PUBLIC
void dvb_add_chartbl(proto_tree *tree, int hf,
        tvbuff_t *tvb, int offset, int length,
        dvb_encoding_e  encoding);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DVB_CHARTBL_H__ */

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
