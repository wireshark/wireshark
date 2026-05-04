/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_K12_H__
#define __W_K12_H__

#include "wtap.h"

/**
 * @brief Open a K12 file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val k12_open(wtap *wth, int *err, char **err_info);

/**
 * @brief Open a K12 file for reading text.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val k12text_open(wtap *wth, int *err, char **err_info);

#endif

