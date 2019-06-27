/* busmaster.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BUSMASTER_H__
#define BUSMASTER_H__

#include <wiretap/wtap.h>

wtap_open_return_val
busmaster_open(wtap *wth, int *err, char **err_info);

#endif  /* BUSMASTER_H__ */
