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

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
#include "config.h"

#include <iosfwd>
#include <iostream>
#include <zlib.h>  // For Z_DEFLATED, etc.
#ifdef HAVE_MINIZIP
#include <minizip/unzip.h>
#include <minizip/zip.h>
#else
#include <minizip-ng/mz_compat.h>
#endif
#include "epan/prefs.h"
#include "wsutil/file_util.h"

#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QMap>

/* Whether we are using minizip-ng and it uses an incompatible 'dos_date'
 * struct member. */
#ifdef HAVE_MZCOMPAT_DOS_DATE
#define _MZDOSDATE dos_date
#else
#define _MZDOSDATE dosDate
#endif

bool WiresharkZipHelper::unzip(QString zipFile, QString directory, bool (*fileCheck)(QString, int), QString (*cleanName)(QString))
{
    unzFile uf = Q_NULLPTR;
    QFileInfo fi(zipFile);
    QDir di(directory);
    int files = 0;

    if (! fi.exists() || ! di.exists())
        return false;

    if ((uf = unzOpen64(zipFile.toUtf8().constData())) == Q_NULLPTR)
        return false;

    unz_global_info64 gi;
    int err;
    unzGetGlobalInfo64(uf,&gi);
    unsigned int nmbr = static_cast<unsigned int>(gi.number_entry);
    if (nmbr <= 0)
        return false;

    QMap<QString, QString> cleanPaths;

    for (unsigned int cnt = 0; cnt < nmbr; cnt++)
    {
        char filename_inzip[256];
        unz_file_info64 file_info;
        err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip),
                                      Q_NULLPTR, 0, Q_NULLPTR, 0);
        if (err == UNZ_OK)
        {
            QString fileInZip(filename_inzip);
            int fileSize = static_cast<int>(file_info.uncompressed_size);

            /* Sanity check for the file */
            if (fileInZip.length() == 0 || (fileCheck && ! fileCheck(fileInZip, fileSize)) )
            {
                if ((cnt + 1) < nmbr)
                {
                    err = unzGoToNextFile(uf);
                    if (err != UNZ_OK)
                    {
                        break;
                    }
                }
                continue;
            }

            if (di.exists())
            {
#ifdef _WIN32
                /* This is an additional fix for bug 16608, in which exports did contain the full path they
                 * where exported from, leading to imports not possible if the path does not exist on that
                 * machine */

                if (fileInZip.contains(":/") || fileInZip.contains(":\\"))
                {
                    QFileInfo fileName(fileInZip);
                    QFileInfo path(fileName.dir(), "");
                    QString newFile = path.baseName() + "/" + fileName.baseName();
                    fileInZip = newFile;
                }
#endif

                QString fullPath = di.path() + "/" + fileInZip;
                QFileInfo fi(fullPath);
                QString dirPath = fi.absolutePath();

                /* clean up name from import. e.g. illegal characters in name */
                if (cleanName)
                {
                    if (! cleanPaths.keys().contains(dirPath))
                    {
                        QString tempPath = cleanName(dirPath);
                        int cnt = 1;
                        while (QFile::exists(tempPath))
                        {
                            tempPath = cleanName(dirPath) + QString::number(cnt);
                            cnt++;
                        }
                        cleanPaths.insert(dirPath, tempPath);
                    }

                    dirPath = cleanPaths[dirPath];
                    if (dirPath.length() == 0)
                        continue;

                    fi = QFileInfo(dirPath + "/" + fi.fileName());
                    fullPath = fi.absoluteFilePath();
                }
                if (fullPath.length() == 0)
                    continue;

                QDir tP(fi.absolutePath());
                if (! tP.exists())
                    di.mkpath(fi.absolutePath());

                if (fileInZip.contains("/"))
                {
                    QString filePath = fi.absoluteFilePath();
                    QFile file(filePath);
                    if (! file.exists())
                    {
                        err = unzOpenCurrentFile(uf);
                        if (err == UNZ_OK)
                        {
                            if (file.open(QIODevice::WriteOnly))
                            {
                                QByteArray buf;
                                buf.resize(IO_BUF_SIZE);
                                while ((err = unzReadCurrentFile(uf, buf.data(), static_cast<int>(buf.size()))) != UNZ_EOF)
                                    file.write(buf.constData(), err);

                                file.close();
                            }
                            unzCloseCurrentFile(uf);

                            files++;
                        }
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

static uint32_t qDateToDosDate(QDateTime time)
{
    QDate ld = time.toLocalTime().date();

    int year = ld.year() - 1900;
    if (year >= 1980)
        year -= 1980;
    else if (year >= 80)
        year -= 80;
    else
        year += 20;

    int month = ld.month() - 1;
    int day = ld.day();

    if (year < 0 || year > 127 || month < 1 || month > 31)
        return 0;

    QTime lt = time.toLocalTime().time();

    unsigned int dosDate = static_cast<unsigned int>((day + (32 * (month + 1)) + (512 * year)));
    unsigned int dosTime = static_cast<unsigned int>((lt.second() / 2) + (32 * lt.minute()) + (2048 * lt.hour()));

    return (uint32_t)(dosDate << 16 | dosTime);
}

void WiresharkZipHelper::addFileToZip(zipFile zf, QString filepath, QString fileInZip)
{
    QFileInfo fi(filepath);
    zip_fileinfo zi;
    int err = ZIP_OK;

    memset(&zi, 0, sizeof(zi));

    QDateTime fTime = fi.lastModified();
    zi._MZDOSDATE = qDateToDosDate(fTime);

    QFile fh(filepath);
    /* Checks if a large file block has to be written */
    bool isLarge = (fh.size() > UINT32_MAX);

    err = zipOpenNewFileInZip3_64(zf, fileInZip.toUtf8().constData(), &zi,
                                  Q_NULLPTR, 0, Q_NULLPTR, 0, Q_NULLPTR, Z_DEFLATED, 9 , 0,
                                  -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
                                  Q_NULLPTR, 0, static_cast<int>(isLarge));

    if (err != ZIP_OK)
        return;

    if (fh.open(QIODevice::ReadOnly))
    {
        QByteArray buf;
        buf.resize(IO_BUF_SIZE);
        while (! fh.atEnd() && err == ZIP_OK)
        {
            qint64 bytesIn = fh.read(buf.data(), buf.size());
            if (bytesIn > 0 && bytesIn <= buf.size())
            {
                err = zipWriteInFileInZip(zf, buf, (unsigned int) bytesIn);
            }
        }
        fh.close();
    }

    zipCloseFileInZip(zf);
}

bool WiresharkZipHelper::zip(QString fileName, QStringList files, QString relativeTo)
{

    QFileInfo fi(fileName);
    if (fi.exists())
        QFile::remove(fileName);

    zipFile zf = zipOpen(fileName.toUtf8().constData(), APPEND_STATUS_CREATE);
    if (zf == Q_NULLPTR)
        return false;

    for (int cnt = 0; cnt < files.count(); cnt++)
    {
        QFileInfo sf(files.at(cnt));
        QString fileInZip = sf.absoluteFilePath();
        QFileInfo relat(relativeTo);
        fileInZip.replace(relat.absoluteFilePath(), "");
        /* Windows cannot open zip files, if the filenames starts with a separator */
        while (fileInZip.length() > 0 && fileInZip.startsWith("/"))
            fileInZip = fileInZip.right(fileInZip.length() - 1);

        WiresharkZipHelper::addFileToZip(zf, sf.absoluteFilePath(), fileInZip);

    }

    if (zipClose(zf, Q_NULLPTR))
        return false;

    return true;
}

#endif
