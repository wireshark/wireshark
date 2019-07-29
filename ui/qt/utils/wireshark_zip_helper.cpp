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
#include <minizip/zip.h>

#include "epan/prefs.h"
#include "wsutil/file_util.h"

#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>

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
                            while ( ( err = unzReadCurrentFile(uf, buf, IO_BUF_SIZE) ) != UNZ_EOF )
                                file.write(buf, err);

                            file.close();
                        }
                        unzCloseCurrentFile(uf);
                        free(buf);

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

#ifndef UINT32_MAX
#define UINT32_MAX  (0xffffffff)
#endif

/* The following methods are being taken from https://github.com/nmoinvaz/minizip/blob/1.2/minishared.c */
int invalid_date(const struct tm *ptm)
{
#define datevalue_in_range(min, max, value) ((min) <= (value) && (value) <= (max))
    return (!datevalue_in_range(0, 207, ptm->tm_year) ||
            !datevalue_in_range(0, 11, ptm->tm_mon) ||
            !datevalue_in_range(1, 31, ptm->tm_mday) ||
            !datevalue_in_range(0, 23, ptm->tm_hour) ||
            !datevalue_in_range(0, 59, ptm->tm_min) ||
            !datevalue_in_range(0, 59, ptm->tm_sec));
#undef datevalue_in_range
}

uint32_t tm_to_dosdate(const struct tm *ptm)
{
    struct tm fixed_tm;

    /* Years supported:
    * [00, 79]      (assumed to be between 2000 and 2079)
    * [80, 207]     (assumed to be between 1980 and 2107, typical output of old
                     software that does 'year-1900' to get a double digit year)
    * [1980, 2107]  (due to the date format limitations, only years between 1980 and 2107 can be stored.)
    */

    memcpy(&fixed_tm, ptm, sizeof(struct tm));
    if (fixed_tm.tm_year >= 1980) /* range [1980, 2107] */
        fixed_tm.tm_year -= 1980;
    else if (fixed_tm.tm_year >= 80) /* range [80, 99] */
        fixed_tm.tm_year -= 80;
    else /* range [00, 79] */
        fixed_tm.tm_year += 20;

    if (invalid_date(ptm))
        return 0;

    return (uint32_t)(((fixed_tm.tm_mday) + (32 * (fixed_tm.tm_mon + 1)) + (512 * fixed_tm.tm_year)) << 16) |
        ((fixed_tm.tm_sec / 2) + (32 * fixed_tm.tm_min) + (2048 * (uint32_t)fixed_tm.tm_hour));
}

unsigned long qDateToDosDate(QDateTime time)
{
    time_t rawtime = time.toTime_t();
    struct tm * timeinfo;

    timeinfo = localtime(&rawtime);
    timeinfo->tm_year = time.date().year() - 1900;
    timeinfo->tm_mon = time.date().month() - 1;
    timeinfo->tm_mday = time.date().day();

    mktime(timeinfo);

    return tm_to_dosdate(timeinfo);
}

void WireSharkZipHelper::addFileToZip(zipFile zf, QString filepath, QString fileInZip)
{
    QFileInfo fi(filepath);
    zip_fileinfo zi;
    int err = ZIP_OK;

    memset(&zi, 0, sizeof(zi));

    QDateTime fTime = fi.lastModified();
    zi.dosDate = qDateToDosDate(fTime);

    QFile fh(filepath);
    /* Checks if a large file block has to be written */
    bool isLarge = ( fh.size() > UINT32_MAX );

    err = zipOpenNewFileInZip3_64(zf, fileInZip.toUtf8().constData(), &zi,
                                  Q_NULLPTR, 0, Q_NULLPTR, 0, Q_NULLPTR, Z_DEFLATED, 9 , 0,
                                  -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
                                  Q_NULLPTR, 0, static_cast<int>(isLarge));

    if ( err != ZIP_OK )
        return;

    if ( fh.open(QIODevice::ReadOnly) )
    {
        char * buf = static_cast<char *>(malloc(IO_BUF_SIZE));
        while ( ! fh.atEnd() && err == ZIP_OK )
        {
            qint64 bytesIn = fh.read(buf, IO_BUF_SIZE);
            if ( bytesIn > 0 && bytesIn <= IO_BUF_SIZE)
            {
                err = zipWriteInFileInZip(zf, buf, (unsigned int) bytesIn);
            }
        }
        free(buf);
        fh.close();
    }

    zipCloseFileInZip(zf);
}

bool WireSharkZipHelper::zip(QString fileName, QStringList files, QString relativeTo)
{

    QFileInfo fi(fileName);
    if ( fi.exists() )
        QFile::remove(fileName);

    zipFile zf = zipOpen(fileName.toUtf8().constData(), APPEND_STATUS_CREATE);
    if ( zf == Q_NULLPTR )
        return false;

    for ( int cnt = 0; cnt < files.count(); cnt++ )
    {
        QFileInfo sf(files.at(cnt));
        QString fileInZip = sf.absoluteFilePath();
        fileInZip.replace(relativeTo, "");
        /* Windows cannot open zip files, if the filenames starts with a separator */
        while ( fileInZip.length() > 0 && fileInZip.startsWith(QDir::separator()) )
            fileInZip = fileInZip.right(fileInZip.length() - 1);

        WireSharkZipHelper::addFileToZip(zf, sf.absoluteFilePath(), fileInZip);

    }

    if ( zipClose(zf, Q_NULLPTR) )
        return false;

    return true;
}

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
