/** @file
*
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
*/
#ifndef __LOG_3GPP_H__
#define __LOG_3GPP_H__

#include <wtap.h>

/**
 * @brief Open a log file in 3GPP format.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error message if an error occurs.
 * @return The result of opening the file. */
wtap_open_return_val log3gpp_open(wtap* wth, int* err, char** err_info);

#endif /* __LOG_3GPP_H__ */
