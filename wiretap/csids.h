/** @file
 *
 * Copyright (c) 2000 by Mike Hall <mlh@io.com>
 * Copyright (c) Cisco Systems
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __CSIDS_H__
#define __CSIDS_H__

#include "wtap.h"

/**
 * @brief Open a CSIDS file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val csids_open(wtap *wth, int *err, char **err_info);

#endif
