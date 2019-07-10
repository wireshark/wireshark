/* wireshark_zip_helper.cpp
 *
 * Definitions for zip / unzip of files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/wireshark_zip_helper.h>

#ifdef HAVE_MINIZIP
#include "config.h"

#include "glib.h"

#include <iosfwd>
#include <iostream>
#include <minizip/unzip.h>

#include "epan/prefs.h"
#include "wsutil/file_util.h"

#include <QDataStream>
#include <QDir>
#include <QFileInfo>

bool WireSharkZipHelper::unzip(QString zipFile, QString directory, bool (*fileCheck)(QString, int))
{
    unzFile uf = Q_NULLPTR;
    QFileInfo fi(zipFile);
    QDir di(directory);
    int files = 0;

    if ( ! fi.exists() || ! di.exists() )
        return false;

    if ( ( uf = unzOpen64(zipFile.toUtf8().constData()) ) == Q_NULLPTR )
        return false;

    unz_global_info64 gi;
    int err = unzGetGlobalInfo64(uf,&gi);
    unsigned int nmbr = static_cast<unsigned int>(gi.number_entry);
    if (nmbr <= 0)
        return false;

    for ( unsigned int cnt = 0; cnt < nmbr; cnt++ )
    {
        char filename_inzip[256];
        unz_file_info64 file_info;
        err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip),
                                      Q_NULLPTR, 0, Q_NULLPTR, 0);
        if ( err == UNZ_OK )
        {
            QString fileInZip(filename_inzip);
            int fileSize = static_cast<int>(file_info.uncompressed_size);
            /* Sanity check for the filenames as well as the file size (max 512kb) */
            if ( fileCheck && fileCheck(fileInZip, fileSize) && di.exists() )
            {
                QFileInfo fi(di.path() + QDir::separator() + fileInZip);
                QDir tP(fi.absolutePath());
                if ( ! tP.exists() )
                    di.mkpath(fi.absolutePath());

                if ( fileInZip.contains("/") )
                {
                    QString filePath = fi.absoluteFilePath();

                    err = unzOpenCurrentFile(uf);
                    if ( err == UNZ_OK )
                    {
                        char * buf = static_cast<char *>(malloc(IO_BUF_SIZE));
                        QFile file(filePath);
                        if ( file.open(QIODevice::WriteOnly) )
                        {
                            QDataStream out(&file);
                            while ( ( err = unzReadCurrentFile(uf, buf, IO_BUF_SIZE) ) != UNZ_EOF )
                            {
                                QByteArray buffer(buf, err);
                                out << buffer;
                            }

                            file.close();
                        }
                        unzCloseCurrentFile(uf);

                        files++;
                    }
                }
            }
        }

        if ((cnt+1) < nmbr)
        {
            err = unzGoToNextFile(uf);
            if (err!=UNZ_OK)
            {
                break;
            }
        }
    }

    unzClose(uf);

    return files > 0 ? true : false;
}

#endif

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
