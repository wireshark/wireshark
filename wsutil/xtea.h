/* xtea.h
 * Implementation of XTEA cipher
 * By Ahmad Fatoum <ahmad[AT]a3f.at>
 * Copyright 2017 Ahmad Fatoum
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __XTEA_H__
#define __XTEA_H__

/* Actual XTEA is big-endian, nevertheless there exist protocols that treat every block
 * as little endian, so we provide both
 */
#include "ws_symbol_export.h"
#include <glib.h>

WS_DLL_PUBLIC void decrypt_xtea_ecb(guint8 plaintext[8], const guint8 ciphertext[8], const guint32 key[4], guint num_rounds);

WS_DLL_PUBLIC void decrypt_xtea_le_ecb(guint8 plaintext[8], const guint8 ciphertext[8], const guint32 key[4], guint num_rounds);

#endif /* __XTEA_H__ */

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
