/* extcap_base.c
 * Base function for extcaps
 *
 * Copyright 2015, Dario Lombardo
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "extcap-base.h"

#ifdef _WIN32
BOOLEAN IsHandleRedirected(DWORD handle)
{
	HANDLE h = GetStdHandle(handle);
	if (h) {
		BY_HANDLE_FILE_INFORMATION fi;
		if (GetFileInformationByHandle(h, &fi)) {
			return TRUE;
		}
	}
	return FALSE;
}

void attach_parent_console()
{
	BOOL outRedirected, errRedirected;

	outRedirected = IsHandleRedirected(STD_OUTPUT_HANDLE);
	errRedirected = IsHandleRedirected(STD_ERROR_HANDLE);

	if (outRedirected && errRedirected) {
		/* Both standard output and error handles are redirected.
		 * There is no point in attaching to parent process console.
		 */
		return;
	}

	if (AttachConsole(ATTACH_PARENT_PROCESS) == 0) {
		/* Console attach failed. */
		return;
	}

	/* Console attach succeeded */
	if (outRedirected == FALSE) {
		if (!freopen("CONOUT$", "w", stdout)) {
			errmsg_print("WARNING: Cannot redirect to stdout.");
		}
	}

	if (errRedirected == FALSE) {
		if (!freopen("CONOUT$", "w", stderr)) {
			errmsg_print("WARNING: Cannot redirect to strerr.");
		}
	}
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
