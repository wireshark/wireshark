/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_AETHRA_H__
#define __W_AETHRA_H__

#include "wtap.h"

/**
 * @brief Open an Aethra file.
 *
 * @param wth Pointer to a wtap structure.
 * @param err Error code if opening fails.
 * @param err_info Error message if opening fails.
 * @return wtap_open_return_val Result of the open operation.
 */
wtap_open_return_val aethra_open(wtap *wth, int *err, char **err_info);

#endif
