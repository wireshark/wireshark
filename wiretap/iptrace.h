/* iptrace.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __IPTRACE_H__
#define __IPTRACE_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val iptrace_open(wtap *wth, int *err, gchar **err_info);

#endif
