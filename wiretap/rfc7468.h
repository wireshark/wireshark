/* rfc7468.h
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PEM_H__
#define __PEM_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val rfc7468_open(wtap *wth, int *err, gchar **err_info);

#endif

/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
