/* capture_errs.c
 * Routines to return error and warning messages for packet capture
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include "capture_errs.h"

#ifdef _WIN32

char *
cant_load_winpcap_err(const char *app_name)
{
	return g_strdup_printf(
"Unable to load WinPcap (wpcap.dll); %s will not be able to capture\n"
"packets.\n"
"\n"
"In order to capture packets, WinPcap must be installed; see\n"
"\n"
"        http://www.winpcap.org/\n"
"\n"
"or the mirror at\n"
"\n"
"        http://winpcap.mirror.wireshark.org/\n"
"\n"
"or the mirror at\n"
"\n"
"        http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/\n"
"\n"
"for a downloadable version of WinPcap and for instructions on how to install\n"
"WinPcap.",
	    app_name);
}

#endif /* _WIN32 */

#endif /* HAVE_LIBPCAP */
