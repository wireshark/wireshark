/* dot11decrypt_util.h
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef _DOT11DECRYPT_UTIL_H
#define _DOT11DECRYPT_UTIL_H

#include <glib.h>
#include "dot11decrypt_int.h"

void dot11decrypt_construct_aad(
    PDOT11DECRYPT_MAC_FRAME wh,
    guint8 *aad,
    size_t *aad_len);

gboolean
dot11decrypt_prf(const guint8 *key, size_t key_len,
                 const char *label,
                 const guint8 *context, size_t context_len,
                 int hash_algo,
                 guint8 *output, size_t output_len);

gboolean
dot11decrypt_kdf(const guint8 *key, size_t key_len,
                 const char *label,
                 const guint8 *context, size_t context_len,
                 int hash_algo,
                 guint8 *output, size_t output_len);

#endif /* _DOT11DECRYPT_UTIL_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
