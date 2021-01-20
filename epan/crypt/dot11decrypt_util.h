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

gboolean
dot11decrypt_derive_pmk_r0(const guint8 *xxkey, size_t xxkey_len,
                           const guint8 *ssid, size_t ssid_len,
                           const guint8 mdid[2],
                           const guint8 *r0kh_id, size_t r0kh_id_len,
                           const guint8 s0kh_id[DOT11DECRYPT_MAC_LEN],
                           int hash_algo,
                           guint8 *pmk_r0,
                           size_t *pmk_r0_len,
                           guint8 pmk_r0_name[16]);

gboolean
dot11decrypt_derive_pmk_r1(const guint8 *pmk_r0, size_t pmk_r0_len,
                           const guint8 *pmk_r0_name,
                           const guint8 *r1kh_id, const guint8 *s1kh_id,
                           int hash_algo,
                           guint8 *pmk_r1, size_t *pmk_r1_len,
                           guint8 *pmk_r1_name);

gboolean
dot11decrypt_derive_ft_ptk(const guint8 *pmk_r1, size_t pmk_r1_len,
                           const guint8 *pmk_r1_name,
                           const guint8 *snonce, const guint8 *anonce,
                           const guint8 *bssid, const guint8 *sta_addr,
                           int hash_algo,
                           guint8 *ptk, const size_t ptk_len, guint8 *ptk_name);
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
