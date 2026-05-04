/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_CAT_DCT2K_H__
#define __W_CAT_DCT2K_H__

#include "wtap.h"

/**
 * @brief Open a Catapult DCT2000 file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val catapult_dct2000_open(wtap *wth, int *err, char **err_info);

#define DCT2000_ENCAP_UNHANDLED 0
#define DCT2000_ENCAP_SSCOP     101
#define DCT2000_ENCAP_MTP2      102
#define DCT2000_ENCAP_NBAP      103

#endif

