/* autosar_dlt.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for DLT file format as defined by AUTOSAR et. al.
 * Copyright (c) 2022-2022 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * Sources for specification:
  * https://www.autosar.org/fileadmin/user_upload/standards/classic/21-11/AUTOSAR_SWS_DiagnosticLogAndTrace.pdf
  * https://www.autosar.org/fileadmin/user_upload/standards/foundation/21-11/AUTOSAR_PRS_LogAndTraceProtocol.pdf
  * https://github.com/COVESA/dlt-viewer
  */

#ifndef __W_AUTOSAR_DLT_H__
#define __W_AUTOSAR_DLT_H__

#include "wtap.h"

wtap_open_return_val autosar_dlt_open(wtap *wth, int *err, gchar **err_info);

#endif

  /*
   * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
   *
   * Local variables:
   * c-basic-offset: 4
   * tab-width: 8
   * indent-tabs-mode: nil
   * End:
   *
   * vi: set shiftwidth=4 tabstop=8 expandtab:
   * :indentSize=4:tabSize=8:noTabs=true:
   */
