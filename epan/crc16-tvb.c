/* crc16-tvb.c
 * CRC-16 tvb routines
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 *  "A Painless Guide to CRC Error Detection Algorithms", Ross Williams
 *      http://www.repairfaq.org/filipg/LINK/F_crc_v3.html
 *
 *  ITU-T Recommendation V.42 (2002), "Error-Correcting Procedures for
 *      DCEs using asynchronous-to-synchronous conversion", Para. 8.1.1.6.1
 */

#include "config.h"

#include <glib.h>
#include <epan/tvbuff.h>
#include <wsutil/crc16.h>
#include <epan/crc16-tvb.h>
#include <wsutil/crc16-plain.h>


uint16_t crc16_ccitt_tvb(tvbuff_t *tvb, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, 0, len);

    return crc16_ccitt(buf, len);
}

uint16_t crc16_x25_ccitt_tvb(tvbuff_t *tvb, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, 0, len);

    return crc16_x25_ccitt_seed(buf, len, 0xFFFF);
}

uint16_t crc16_r3_ccitt_tvb(tvbuff_t *tvb, int offset, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_x25_ccitt_seed(buf, len, 0);
}

uint16_t crc16_ccitt_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_ccitt(buf, len);
}

uint16_t crc16_ccitt_tvb_seed(tvbuff_t *tvb, unsigned len, uint16_t seed)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, 0, len);

    return crc16_ccitt_seed(buf, len, seed);
}

uint16_t crc16_ccitt_tvb_offset_seed(tvbuff_t *tvb, unsigned offset, unsigned len, uint16_t seed)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_ccitt_seed(buf, len, seed);
}

uint16_t crc16_iso14443a_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_iso14443a(buf, len);
}

uint16_t crc16_usb_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_usb(buf, len);
}

uint16_t crc16_plain_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    uint16_t crc = crc16_plain_init();
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    crc = crc16_plain_update(crc, buf, len);

    return crc16_plain_finalize(crc);
}

uint16_t crc16_plain_tvb_offset_seed(tvbuff_t *tvb, unsigned offset, unsigned len, uint16_t crc)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    crc = crc16_plain_update(crc, buf, len);

    return crc16_plain_finalize(crc);
}

uint16_t crc16_0x9949_tvb_offset_seed(tvbuff_t *tvb, unsigned offset, unsigned len, uint16_t seed)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_0x9949_seed(buf, len, seed);
}

uint16_t crc16_0x3D65_tvb_offset_seed(tvbuff_t *tvb, unsigned offset, unsigned len, uint16_t seed)
{
    const uint8_t *buf;

    tvb_ensure_bytes_exist(tvb, offset, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, offset, len);

    return crc16_0x3D65_seed(buf, len, seed);
}

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
