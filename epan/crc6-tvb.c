/* crc6-tvb.c
 * CRC-6 tvb routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <epan/tvbuff.h>
#include <wsutil/crc6.h>
#include <epan/crc6-tvb.h>

guint16
crc6_compute_tvb(tvbuff_t *tvb, int len)
{
    const guint8 *buf;

    tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
    buf = tvb_get_ptr(tvb, 0, len);

    return crc6_0X6F(0, buf, len);
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
