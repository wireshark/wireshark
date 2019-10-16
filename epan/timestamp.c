/* timestamp.c
 * Routines for timestamp type setting.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "timestamp.h"

/* Init with an invalid value, so that "recent" in ui/gtk/menu.c can detect this
 * and distinguish it from a command line value */
static ts_type timestamp_type = TS_NOT_SET;

static int timestamp_precision = TS_PREC_AUTO;

static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;

ts_type timestamp_get_type(void)
{
	return timestamp_type;
}

void timestamp_set_type(ts_type ts_t)
{
	timestamp_type = ts_t;
}


int timestamp_get_precision(void)
{
	return timestamp_precision;
}

void timestamp_set_precision(int tsp)
{
	timestamp_precision = tsp;
}


ts_seconds_type timestamp_get_seconds_type(void)
{
	return timestamp_seconds_type;
}

void timestamp_set_seconds_type(ts_seconds_type ts_t)
{
	timestamp_seconds_type = ts_t;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
