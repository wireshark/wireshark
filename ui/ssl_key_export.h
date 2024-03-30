/** @file
 *
 * SSL session key utilities. Copied from ui/gkt/export_sslkeys.c
 * by Sake Blok <sake@euronet.nl> (20110526)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SSL_KEY_EXPORT_H__
#define __SSL_KEY_EXPORT_H__

#include "cfile.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Return the number of available SSL session keys.
 *
 * @return The number of available SSL session keys.
 */
extern int ssl_session_key_count(void);

/** Dump our SSL Session Keys to a string
 *
 * @param[out] length Length of returned string.
 *
 * @return A string containing all the SSL Session Keys. Must be freed with
 * g_free().
 */
extern char* ssl_export_sessions(size_t *length);

/** Add a DSB with the used TLS secrets to a capture file.
 *
 * @param cf The capture file
 */
extern void tls_export_dsb(capture_file *cf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SSL_KEY_EXPORT_H__ */
