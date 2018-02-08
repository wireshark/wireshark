/* params.h
 * Definitions for parameter handling routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PARAMS_H__
#define __PARAMS_H__

/*
 * Definition of a value for an enumerated type.
 *
 * "name" is the the name one would use on the command line for the value.
 * "description" is the description of the value, used in combo boxes/
 * option menus.
 * "value" is the value.
 */
typedef struct {
	const char	*name;
	const char	*description;
	gint		value;
} enum_val_t;

#endif /* params.h */

