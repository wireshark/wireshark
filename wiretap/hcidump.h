/** @file
 *
 * Copyright (c) 2003 by Marcel Holtmann <marcel@holtmann.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __HCIDUMP_H__
#define __HCIDUMP_H__

#include "wtap.h"

/**
 * @brief Open a hcidump file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val hcidump_open(wtap *wth, int *err, char **err_info);

#endif
