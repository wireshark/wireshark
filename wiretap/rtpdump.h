/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for RTPDump file format
 * Copyright (c) 2023 by David Perry <boolean263@protonmail.com
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTPDUMP_H__
#define RTPDUMP_H__

#include <wiretap/wtap.h>

wtap_open_return_val
rtpdump_open(wtap *wth, int *err, char **err_info);

#endif  /* RTPDUMP_H__ */
