/* candump.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for candump log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CANDUMP_H__
#define CANDUMP_H__

#include <wiretap/wtap.h>

wtap_open_return_val
candump_open(wtap *wth, int *err, char **err_info);

#endif  /* CANDUMP_H__ */
