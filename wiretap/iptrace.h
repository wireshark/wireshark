/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __IPTRACE_H__
#define __IPTRACE_H__

#include "wtap.h"

/**
 * @brief Open an IPTRACE file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if the file is not mine or a short read occurs.
 * @param err_info Error information string if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val iptrace_open(wtap *wth, int *err, char **err_info);

#endif
