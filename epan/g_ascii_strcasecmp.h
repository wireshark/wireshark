/*
 * $Id$
 *
 * "g_ascii_strcasecmp()" and "g_ascii_strncasecmp()" extracted from
 * GLib 2.4.8, for use with GLibs that don't have it (e.g., GLib 1.2[.x]).
 */

#ifndef __WIRESHARK_G_ASCII_STRCASECMP_H__
#define __WIRESHARK_G_ASCII_STRCASECMP_H__

extern gint g_ascii_strcasecmp (const gchar *s1,
				const gchar *s2);

extern gint g_ascii_strncasecmp (const gchar *s1,
				 const gchar *s2,
				 gsize n);

#endif
