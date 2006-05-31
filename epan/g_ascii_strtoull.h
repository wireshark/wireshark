/*
 * $Id$
 *
 * "g_ascii_strtoull()" extracted from GLib 2.4.5, for use with GLibs
 * that don't have it (e.g., GLib 1.2[.x]).
 */

#ifndef __WIRESHARK_G_ASCII_STRTOULL_H__
#define __WIRESHARK_G_ASCII_STRTOULL_H__

extern guint64 g_ascii_strtoull (const gchar *nptr,
				 gchar      **endptr,
				 guint        base);

#endif
