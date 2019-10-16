/* log_3gpp.h
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

wtap_open_return_val log3gpp_open(wtap* wth, int* err, gchar** err_info);

#endif /* __LOG_3GPP_H__ */
