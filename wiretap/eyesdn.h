/* eyesdn.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_EYESDN_H__
#define __W_EYESDN_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val eyesdn_open(wtap *wth, int *err, gchar **err_info);

enum EyeSDN_TYPES {
    EYESDN_ENCAP_ISDN=0,
    EYESDN_ENCAP_MSG,
    EYESDN_ENCAP_LAPB,
    EYESDN_ENCAP_ATM,
    EYESDN_ENCAP_MTP2,
    EYESDN_ENCAP_DPNSS,
    EYESDN_ENCAP_DASS2,
    EYESDN_ENCAP_BACNET,
    EYESDN_ENCAP_V5_EF
};

gboolean eyesdn_dump_open(wtap_dumper *wdh, int *err);
int eyesdn_dump_can_write_encap(int encap);

#endif
