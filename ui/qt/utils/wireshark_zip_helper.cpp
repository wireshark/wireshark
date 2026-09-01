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
// The original minizip API uses constants defined in zlib.h like Z_DEFLATED.
// The original minizip's zip.h and unzip.h include zlib.h, but minizip-ng's
// do not until 4.0.8.
// https://github.com/zlib-ng/minizip-ng/commit/91112baa265fcea729f534ceb085c54f4fd285d3
//
// The minizip-ng library itself does include either zlib.h or zlib-ng.h, depending
// on which one was linked against when building.
// The zlib.h included with the MacOS SDK is built without ZLIB_CONST so it's
// not ABI compatible with zlib.h that do define ZLIB_CONST (or with zlib-ng.h
// in general) so if we include one here, we have to include the same one used
// when building minizip-ng.
// Fedora and Red Hat Linux provide minizip-ng and zlib-ng as minizip and zlib,
// respectively, so HAVE_MINIZIP being defined doesn't necessarily mean we have
// the original minizip instead of minizip-ng.
#ifdef HAVE_MINIZIP
#include <minizip/unzip.h>
#include <minizip/zip.h>
#if !defined(Z_DEFLATED) || !defined(Z_DEFAULT_STRATEGY)
#include <zlib.h>  // For Z_DEFLATED, etc.
#endif /* !defined(Z_DEFLATED) || !defined(Z_DEFAULT_STRATEGY) */
#else /* HAVE_MINIZIP */
#include <minizip-ng/unzip.h>
#include <minizip-ng/zip.h>
#if !defined(Z_DEFLATED) || !defined(Z_DEFAULT_STRATEGY)
#ifdef HAVE_ZLIBNG
#include <zlib-ng.h>  // For Z_DEFLATED, etc.
#else /* HAVE_ZLIBNG */
#include <zlib.h>  // For Z_DEFLATED, etc.
#endif /* HAVE_ZLIBNG */
#endif /* !defined(Z_DEFLATED) || !defined(Z_DEFAULT_STRATEGY) */
#endif /* HAVE_MINIZIP */
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

bool WiresharkZipHelper::unzip(QString zipFile, QString directory, bool (*fileCheck)(QString, uint64_t), QString (*cleanName)(QString))
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
    QString canonicalDir = di.canonicalPath();
    if (canonicalDir.isEmpty()) {
        // Effectively re-checks !di.exists()
        return false;
    }
    if (!canonicalDir.endsWith('/')) {
        canonicalDir += '/';
    }

    for (unsigned int cnt = 0; cnt < nmbr; cnt++)
    {
        char filename_inzip[256];
        unz_file_info64 file_info;
        err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip),
                                      Q_NULLPTR, 0, Q_NULLPTR, 0);
        if (err == UNZ_OK)
        {
            QString fileInZip(filename_inzip);
            uint64_t fileSize = file_info.uncompressed_size;

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

            /* ZIP archives created by Wireshark *should* have paths relative
             * to the profiles directory. This was not the case prior to 3.2.5
             * (issue #16608) on Windows, probably due to directory separators
             * or case-insensitivity or similar.
             */
            if (QDir::isAbsolutePath(fileInZip)) {
#ifdef _WIN32
                /* We use the last directory as the profile name (there should
                 * not be multiple levels) to workaround the issue and allow
                 * importing the profile even if the higher level directory
                 * structure doesn't match.
                 * XXX - Remove this, since bad profile ZIP files haven't been
                 * produced since 3.2.4? */
                QFileInfo fileName(fileInZip);
                if (fileName.fileName().isEmpty()) {
                    // ZIP file entries that are just directories must end in
                    // a directory separator. ("All slashes MUST be forward
                    // slashes" according to APPNOTE.TXT but sometimes there
                    // are broken archives.) Those have empty fileName(); skip.
                    continue;
                }
                QString fileNameDir = fileName.dir().dirName();
                // Note that QDir::dirName never includes a drive letter
                // but is empty at a drive root. We should always have a
                // profile name here in an archive created by Wireshark.
                if (fileNameDir.isEmpty()) {
                    continue;
                }
                fileInZip = QStringLiteral("%1/%2").arg(fileNameDir, fileName.fileName());
#else
                continue;
#endif
            }
            if (di.exists()) // XXX - Do we need to test this yet again?
            {
                // Reject paths outside the extraction root, to prevent directory
                // traversal attacks. The full path shouldn't exist yet, so no
                // using canonical* functions, and the absolute* functions don't
                // guarantee removing "..", etc., so use QDir::cleanPath.
                // Note we ensured canonicalDir ends with '/'.
                QString fullPath = QDir::cleanPath(QStringLiteral("%1%2").arg(canonicalDir, fileInZip));
                if (!fullPath.startsWith(canonicalDir)) {
                    continue;
                }
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
                            tempPath = QStringLiteral("%1%2").arg(cleanName(dirPath)).arg(cnt);
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
        // XXX - Do some additional tests to verify that this actually rmeoves
        // a path. It should work correctly now and there are only internal
        // callers so warn if it fails.
        fileInZip.replace(relat.absoluteFilePath(), "");
        /* Windows cannot open zip files if the filenames starts with a separator */
        while (fileInZip.length() > 0 && fileInZip.startsWith("/"))
            fileInZip = fileInZip.right(fileInZip.length() - 1);

        WiresharkZipHelper::addFileToZip(zf, sf.absoluteFilePath(), fileInZip);

    }

    if (zipClose(zf, Q_NULLPTR))
        return false;

    return true;
}

#endif
