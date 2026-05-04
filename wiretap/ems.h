/** @file
 *
 * EMS file format decoder for the Wiretap library.
 *
 * Copyright (c) 2023 by Timo Warns <timo.warns@gmail.com>
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_EMS_H__
#define __W_EMS_H__

#include "wtap.h"

/**
 * @brief Open an EMS file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val ems_open(wtap *wth, int *err, char **err_info);

#endif
