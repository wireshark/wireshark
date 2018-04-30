/* export_sslkeys.h
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
 * @return A string containing all the SSL Session Keys. Must be freed with
 * g_free().
 */
extern gchar* ssl_export_sessions(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SSL_KEY_EXPORT_H__ */

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
