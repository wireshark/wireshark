/** @file
 *
 * ISO/IEC 13818-1 MPEG2-TS file format decoder for the Wiretap library.
 * Written by Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2012 Weston Schmidt
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MP2T_H__
#define __W_MP2T_H__

#include "wtap.h"

/**
 * @brief Opens an MPEG-2 Transport Stream file.
 *
 * Attempts to open a file as an MPEG-2 Transport Stream and initializes the wtap structure accordingly.
 *
 * @param wth Pointer to the wtap structure that will be initialized.
 * @param err Error code if the file is not an MPEG-2 Transport Stream.
 * @param err_info Error message if the file is not an MPEG-2 Transport Stream.
 * @return wtap_open_return_val The result of opening the file, indicating success or failure.
 */
wtap_open_return_val mp2t_open(wtap *wth, int *err, char **err_info);

#endif
