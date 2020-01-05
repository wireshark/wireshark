/* please_report_bug.c
 * Routines returning strings to use when reporting a bug.
 * They ask the user to report a bug to the Wireshark developers.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "please_report_bug.h"

/*
 * Long message, to use in alert boxes and printed messages.
 */
const char *
please_report_bug(void)
{
	return
	    "Please report this to the Wireshark developers as a bug.\n"
            "https://bugs.wireshark.org/\n"
            "(This is not a crash; please do not say, in your report, that it is a crash.)";
}

/*
 * Short message, to use in status bar messages.
 */
const char *
please_report_bug_short(void)
{
	return "Please report this to the Wireshark developers.";
}
