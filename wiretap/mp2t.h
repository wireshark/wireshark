/** @file
 *
 * ISO/IEC 13818-1 MPEG2-TS file format decoder for the Wiretap library.
 * Written by Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2012 Weston Schmidt
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MP2T_H__
#define __W_MP2T_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val mp2t_open(wtap *wth, int *err, char **err_info);

#endif
