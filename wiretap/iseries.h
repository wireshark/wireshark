/** @file
 *
 * Wiretap Library
 * Copyright (c) 2005 by Martin Warnes <martin@warnes.homeip.net>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_ISERIES_H__
#define __W_ISERIES_H__

#include "wtap.h"

/**
 * @brief Open an iSeries trace file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val iseries_open(wtap *wth, int *err, char **err_info);

#endif
