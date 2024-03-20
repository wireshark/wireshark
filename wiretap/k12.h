/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_K12_H__
#define __W_K12_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val k12_open(wtap *wth, int *err, char **err_info);
wtap_open_return_val k12text_open(wtap *wth, int *err, char **err_info);

#endif

