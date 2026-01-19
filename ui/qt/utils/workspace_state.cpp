/* workspace_state.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "workspace_state.h"

#include <algorithm>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QRegularExpression>
#include <QtConcurrent>
#include <QThreadPool>

#include <wsutil/filesystem.h>
#include <app/application_flavor.h>

#include <ui/recent.h>
#include <epan/prefs.h>

WorkspaceState::WorkspaceState(QObject *parent)
    : QObject(parent)
{
}

WorkspaceState::~WorkspaceState()
{
}

WorkspaceState* WorkspaceState::instance()
{
    // Meyer's Singleton - thread-safe in C++11 and later
    static WorkspaceState* instance_ = new WorkspaceState();
    return instance_;
}

QString WorkspaceState::recentCommonFilePath() const
{
    // recent_common is NOT profile-specific (from_profile = false)
    char *rf_path = get_persconffile_path(
        RECENT_COMMON_FILE_NAME,
        false,  // from_profile = false
        application_configuration_environment_prefix()
    );

    QString path = QString::fromUtf8(rf_path);
    g_free(rf_path);

    return path;
}

QString WorkspaceState::recentProfileFilePath() const
{
    // recent is profile-specific (from_profile = true)
    char *rf_path = get_persconffile_path(
        RECENT_PROFILE_FILE_NAME,
        true,  // from_profile = true
        application_configuration_environment_prefix()
    );

    QString path = QString::fromUtf8(rf_path);
    g_free(rf_path);

    return path;
}

bool WorkspaceState::parseRecentFile(const QString &filePath,
                                     std::function<void(const QString &key, const QString &value)> handler)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream in(&file);
    // Match: key: value (with optional whitespace)
    static const QRegularExpression keyValueRe(QStringLiteral("^([^:]+):\\s*(.*)$"));

    while (!in.atEnd()) {
        QString line = in.readLine();

        // Skip empty lines and comments
        if (line.isEmpty() || line.startsWith('#')) {
            continue;
        }

        QRegularExpressionMatch match = keyValueRe.match(line);
        if (match.hasMatch()) {
            QString key = match.captured(1).trimmed();
            QString value = match.captured(2);
            handler(key, value);
        }
    }

    file.close();
    return true;
}

bool WorkspaceState::loadCommonState(QString *errorPath, int *errorCode)
{
    QString filePath = recentCommonFilePath();

    QFile file(filePath);
    if (!file.exists()) {
        // File doesn't exist yet - not an error, just no state to load
        return true;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (errorPath) *errorPath = filePath;
        if (errorCode) *errorCode = errno;
        return false;
    }
    file.close();

    // Clear existing state before loading
    QList<RecentFileInfo> newFileList;

    bool success = parseRecentFile(filePath, [&newFileList](const QString &key, const QString &value) {
        if (key == KEY_CAPTURE_FILE) {
            // Recent files are stored oldest first, newest last
            // We append to maintain that order
            if (!value.isEmpty()) {
                RecentFileInfo info;
                info.size = 0;
                info.accessible = false;
                info.filename = value;
                newFileList.append(info);
            }
        }
        // Future: handle other keys here
        // else if (key == KEY_DISPLAY_FILTER) { ... }
    });

    if (success) {
        recent_capture_files_.clear();
        recent_capture_files_.append(newFileList);

        // Queue async status checks for all loaded files
        for (const RecentFileInfo &info : newFileList) {
            queueFileStatusCheck(info.filename);
        }

        emit stateLoaded();
    }

    return success;
}

const QList<RecentFileInfo>& WorkspaceState::recentCaptureFiles() const
{
    return recent_capture_files_;
}

QStringList WorkspaceState::recentCaptureFilenames() const
{
    QStringList filenames;

    for (const RecentFileInfo &info : recent_capture_files_) {
        filenames.append(info.filename);
    }
    return filenames;
}

void WorkspaceState::addRecentCaptureFile(const QString &filePath)
{
    if (filePath.isEmpty()) {
        return;
    }

    // Remove existing entry if present (Qt5-compatible approach)
    auto matchesPath = [&filePath](const RecentFileInfo &info) {
#ifdef Q_OS_WIN
        return info.filename.compare(filePath, Qt::CaseInsensitive) == 0;
#else
        return info.filename == filePath;
#endif
    };
    recent_capture_files_.erase(
        std::remove_if(recent_capture_files_.begin(), recent_capture_files_.end(), matchesPath),
        recent_capture_files_.end());

    // Add to end (newest last, matching the file format)
    RecentFileInfo info;
    info.size = 0;
    info.accessible = false;
    info.filename = filePath;
    recent_capture_files_.append(info);

    // Trim to max size (remove oldest = front of list)
    int maxRecentFiles = static_cast<int>(prefs.gui_recent_files_count_max);
    if (recent_capture_files_.size() > maxRecentFiles) {
        recent_capture_files_ = recent_capture_files_.mid(recent_capture_files_.size() - maxRecentFiles);
    }

    // Queue async status check for the newly added file
    queueFileStatusCheck(filePath);

    emit recentCaptureFilesChanged();
    write_recent();  // Persist immediately
}

void WorkspaceState::removeRecentCaptureFile(const QString &filePath)
{
    // Qt5-compatible approach using std::remove_if
    auto matchesPath = [&filePath](const RecentFileInfo &info) {
#ifdef Q_OS_WIN
        return info.filename.compare(filePath, Qt::CaseInsensitive) == 0;
#else
        return info.filename == filePath;
#endif
    };
    auto originalSize = recent_capture_files_.size();
    auto newEnd = std::remove_if(recent_capture_files_.begin(), recent_capture_files_.end(), matchesPath);
    recent_capture_files_.erase(newEnd, recent_capture_files_.end());

    if (recent_capture_files_.size() < originalSize) {
        emit recentCaptureFilesChanged();
        write_recent();  // Persist immediately
    }
}

void WorkspaceState::clearRecentCaptureFiles()
{
    if (!recent_capture_files_.isEmpty()) {
        recent_capture_files_.clear();
        emit recentCaptureFilesChanged();
        write_recent();  // Persist immediately
    }
}

void WorkspaceState::queueFileStatusCheck(const QString &filename)
{
    // Force deep copy for thread safety
    QString filenameCopy = QString::fromStdU16String(filename.toStdU16String());

    QThreadPool::globalInstance()->start([this, filenameCopy]() {
        QFileInfo fileInfo(filenameCopy);
        qint64 size = 0;
        bool accessible = false;

        if (fileInfo.isFile() && fileInfo.isReadable()) {
            size = fileInfo.size();
            accessible = true;
        }

        // Queue the result back to the main thread
        QMetaObject::invokeMethod(this, [this, filenameCopy, size, accessible]() {
            onFileStatusChecked(filenameCopy, size, accessible);
        }, Qt::QueuedConnection);
    });
}

void WorkspaceState::onFileStatusChecked(const QString &filename, qint64 size, bool accessible)
{
    for (RecentFileInfo &info : recent_capture_files_) {
#ifdef Q_OS_WIN
        if (info.filename.compare(filename, Qt::CaseInsensitive) == 0) {
#else
        if (info.filename == filename) {
#endif
            if (info.size != size || info.accessible != accessible) {
                info.size = size;
                info.accessible = accessible;
                emit recentFileStatusChanged(filename);
            }
            break;
        }
    }
}
