/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __RADCOM_H__
#define __RADCOM_H__

#include "wtap.h"

/**
 * @brief Open a RADCOM file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating whether the file is opened successfully or not.
 */
wtap_open_return_val radcom_open(wtap *wth, int *err, char **err_info);

#endif
