/** @file
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __PPPDUMP_H__
#define __PPPDUMP_H__

#include "wtap.h"

/**
 * @brief Open a PPP dump file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val pppdump_open(wtap *wth, int *err, char **err_info);

#endif
