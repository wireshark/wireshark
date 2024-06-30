/** @file
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

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)

#ifdef HAVE_MINIZIP
#include "minizip/zip.h"
#else
#include "minizip-ng/mz_compat.h"
#endif

class WiresharkZipHelper
{
public:
    static bool zip(QString zipFile, QStringList files, QString relativeTo = QString());
    static bool unzip(QString zipFile, QString directory, bool (*fileCheck)(QString fileName, int fileSize) = Q_NULLPTR, QString (*cleanName)(QString name) = Q_NULLPTR);

protected:
    static void addFileToZip(zipFile zf, QString filepath, QString fileInZip);

};

#endif

#endif // WS_ZIP_HELPER_H
