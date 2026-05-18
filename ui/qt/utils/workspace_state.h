/** @file
 *
 * Workspace state management - handles persistent UI state between sessions
 *
 * This provides Qt-native access to the state files managed by ui/recent.c.
 * Currently runs parallel to the existing C code for gradual migration.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WORKSPACE_STATE_H
#define WORKSPACE_STATE_H

#include "config.h"

#include <QObject>
#include <QStringList>
#include <QFileInfo>
#include <QList>
#include <functional>

/**
 * @brief Information about a recent capture file.
 *
 * Stores the filename along with cached status information
 * (size and accessibility) that is updated asynchronously.
 */
struct RecentFileInfo {
    QString filename;   /**< Absolute path to the capture file. */
    qint64  size = 0;   /**< Cached file size in bytes; 0 until the async status check completes. */
    bool accessible = false; /**< @c true if the file exists and is readable at last status check. */
};


/**
 * @brief Manages workspace state that persists between sessions.
 *
 * This class provides Qt-native access to the "recent" settings.
 * It currently runs parallel to ui/recent.c for gradual migration.
 *
 * Usage:
 *   WorkspaceState::instance()->loadCommonState();
 *   QStringList files = WorkspaceState::instance()->recentCaptureFiles();
 *
 * The singleton pattern avoids adding more dependencies to MainApplication.
 */
class WorkspaceState : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Returns the singleton instance.
     *
     * Thread-safe in C++11 and later (Meyer's Singleton).
     */
    static WorkspaceState *instance();

    /**
     * @brief Destroys the singleton and releases all owned resources.
     */
    virtual ~WorkspaceState();

    /**
     * @brief Deleted copy constructor to enforce the singleton pattern.
     */
    WorkspaceState(const WorkspaceState &) = delete;

    /**
     * @brief Deleted assignment operator to enforce the singleton pattern.
     */
    WorkspaceState &operator=(const WorkspaceState &) = delete;

    /**
     * @brief Load state from the recent_common file.
     *
     * Call this during application startup after recent_read_static() has been called.
     *
     * @param[out] errorPath If loading fails, contains the path that failed.
     * @param[out] errorCode If loading fails, contains the errno.
     * @return @c true on success, @c false on failure.
     */
    bool loadCommonState(QString *errorPath = nullptr, int *errorCode = nullptr);

    /**
     * @brief Get the path to the recent_common file.
     *
     * @return Full path to the recent_common file.
     */
    QString recentCommonFilePath() const;

    /**
     * @brief Get the path to the profile-specific recent file.
     *
     * @return Full path to the recent file for the current profile.
     */
    QString recentProfileFilePath() const;

    /**
     * @brief Get the list of recently opened capture files.
     *
     * @return List of file info structs, most recent last.
     */
    const QList<RecentFileInfo> &recentCaptureFiles() const;

    /**
     * @brief Get just the filenames of recent capture files.
     *
     * Convenience method for code that only needs the paths.
     *
     * @return List of file paths, most recent last.
     */
    QStringList recentCaptureFilenames() const;

    /**
     * @brief Add a capture file to the recent files list.
     *
     * @param filePath The path to the capture file.
     */
    void addRecentCaptureFile(const QString &filePath);

    /**
     * @brief Remove a capture file from the recent files list.
     *
     * @param filePath The path to remove.
     */
    void removeRecentCaptureFile(const QString &filePath);

    /**
     * @brief Clear all recent capture files.
     */
    void clearRecentCaptureFiles();

    /**
     * @brief Check if this is a development build.
     *
     * Returns true when VERSION_FLAVOR is non-empty (the default
     * "Development Build" set by CMake).  Release builds either leave
     * VERSION_FLAVOR empty or undefine it entirely.
     *
     * @return @c true for development builds, @c false for releases.
     */
    static bool isDevelopmentBuild();

    /**
     * @brief Check if the application is running in portable mode. (Windows only)
     *
     * In portable mode, state files are stored in the application directory
     * instead of a user-specific location. For any other OS than Windows, this will return false.
     *
     * @return @c true if running in portable mode, @c false otherwise.
     */
    static bool isPortableApplication();

signals:
    /**
     * @brief Emitted when the recent capture files list changes.
     */
    void recentCaptureFilesChanged();

    /**
     * @brief Emitted when a file's status (size/accessibility) is updated.
     *
     * @param filename The file whose status was updated.
     */
    void recentFileStatusChanged(const QString &filename);

    /**
     * @brief Emitted when state is loaded from disk.
     */
    void stateLoaded();

    /**
     * @brief Emitted when state is saved to disk.
     */
    void stateSaved();

protected:
    /**
     * @brief Constructs the WorkspaceState; use instance() to obtain the singleton.
     * @param parent Optional parent QObject.
     */
    explicit WorkspaceState(QObject *parent = nullptr);

private slots:
    /**
     * @brief Slot called when async file status check completes.
     * @param filename   Path of the file whose status was checked.
     * @param size       File size in bytes as reported by the async check.
     * @param accessible @c true if the file exists and is readable.
     */
    void onFileStatusChecked(const QString &filename, qint64 size, bool accessible);

private:
    /**
     * @brief Parse a recent file and extract key-value pairs.
     *
     * @param filePath Path to the recent file.
     * @param handler  Callback invoked for each key-value pair found.
     * @return @c true on success, @c false on failure.
     */
    bool parseRecentFile(const QString &filePath,
                         std::function<void(const QString &key, const QString &value)> handler);

    /**
     * @brief Enqueues an asynchronous file-status check for @p filename,
     *        which will emit recentFileStatusChanged() on completion.
     * @param filename Path of the file to check.
     */
    void queueFileStatusCheck(const QString &filename);

    QList<RecentFileInfo> recent_capture_files_; /**< Ordered list of recent capture file records; most recent last. */

    static constexpr const char *RECENT_COMMON_FILE_NAME  = "recent_common";  /**< Basename of the cross-profile recent file. */
    static constexpr const char *RECENT_PROFILE_FILE_NAME = "recent";          /**< Basename of the per-profile recent file. */
    static constexpr const char *KEY_CAPTURE_FILE         = "recent.capture_file"; /**< Key used to persist capture file paths in the recent file. */
};

#endif // WORKSPACE_STATE_H
