/* wireshark_zip_helper.h
 *
 * Definitions for zip / unzip of files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WS_ZIP_HELPER_H
#define WS_ZIP_HELPER_H

#include "config.h"

#include <QDir>

#ifdef HAVE_MINIZIP

class WireSharkZipHelper
{
public:
    static bool unzip(QString zipFile, QString directory, bool (*fileCheck)(QString fileName, int fileSize) );
};

#endif

#endif // WS_ZIP_HELPER_H

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
