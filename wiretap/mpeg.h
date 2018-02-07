/* mpeg.h
 *
 * MPEG file format decoder for the Wiretap library.
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MPEG_H__
#define __W_MPEG_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val mpeg_open(wtap *wth, int *err, gchar **err_info);

#endif
