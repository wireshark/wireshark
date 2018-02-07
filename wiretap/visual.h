/* visual.h
 *
 * File read write routines for Visual Networks .cap files.
 * Copyright 2001, Tom Nisbet  tnisbet@visualnetworks.com
 *
 * Based on the code that handles netmon files.
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __VISUAL_H__
#define __VISUAL_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val visual_open(wtap *wth, int *err, gchar **err_info);
gboolean visual_dump_open(wtap_dumper *wdh, int *err);
int visual_dump_can_write_encap(int encap);

#endif
