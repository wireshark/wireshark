/* privileges.c
 * Routines for handling privileges, e.g. set-UID and set-GID on UNIX.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
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

#include <glib.h>

#include "privileges.h"

#ifdef _WIN32

/*
 * Called when the program starts, to save whatever credential information
 * we'll need later.
 */
void
get_credential_info(void)
{
}

/*
 * For now, we say the program wasn't started with special privileges.
 * There are ways of running programs with credentials other than those
 * for the session in which it's run, but I don't know whether that'd be
 * done with Ethereal/Tethereal or not.
 */
gboolean
started_with_special_privs(void)
{
	return FALSE;
}

/*
 * For now, we don't do anything when asked to relinquish special privileges.
 */
void
relinquish_special_privs_perm(void)
{
}

#else /* _WIN32 */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static uid_t ruid, euid;
static gid_t rgid, egid;

/*
 * Called when the program starts, to save whatever credential information
 * we'll need later.
 * That'd be the real and effective UID and GID on UNIX.
 */
void
get_credential_info(void)
{
	ruid = getuid();
	euid = geteuid();
	rgid = getgid();
	egid = getegid();
}

/*
 * "Started with special privileges" means "started out set-UID or set-GID".
 */
gboolean
started_with_special_privs(void)
{
#ifdef HAVE_ISSETUGID
	return issetugid();
#else
	return (ruid != euid || rgid != egid);
#endif
}

/*
 * Permanently relinquish  set-UID and set-GID privileges.
 * Ignore errors for now - if we have the privileges, we should
 * be able to relinquish them.
 */
void
relinquish_special_privs_perm(void)
{
	setuid(ruid);
	setgid(rgid);
}

#endif /* _WIN32 */
