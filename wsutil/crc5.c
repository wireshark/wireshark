/* crc5.c
 * CRC-5 routine
 *
 * 2019 Tomasz Mon <desowin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <wsutil/crc5.h>

static guint8 crc5_usb_bits(guint32 v, int vl, guint8 ival)
{
    /* This function is based on code posted by John Sullivan to Wireshark-dev
     * mailing list on Jul 21, 2019.
     *
     * "One of the properties of LFSRs is that a 1 bit in the input toggles a
     *  completely predictable set of register bits *at any point in the
     *  future*. This isn't often useful for most CRC caculations on variable
     *  sized input, as the cost of working out which those bits are vastly
     *  outweighs most other methods."
     *
     * In USB 2.0, the CRC5 is calculated on either 11 or 19 bits inputs,
     * and thus this approach is viable.
     */
    guint8 rv = ival;
    static const guint8 bvals[19] = {
        0x1e, 0x15, 0x03, 0x06, 0x0c, 0x18, 0x19, 0x1b,
        0x1f, 0x17, 0x07, 0x0e, 0x1c, 0x11, 0x0b, 0x16,
        0x05, 0x0a, 0x14
    };

    for (int i = 0; i < vl; i++) {
        if (v & (1 << i)) {
            rv ^= bvals[19 - vl + i];
        }
    }
    return rv;
}

guint8 crc5_usb_11bit_input(guint16 input)
{
    return crc5_usb_bits(input, 11, 0x02);
}

guint8 crc5_usb_19bit_input(guint32 input)
{
    return crc5_usb_bits(input, 19, 0x1d);
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
