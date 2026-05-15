/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILE_H
#define CAPTURE_FILE_H

#include <QObject>

#include <config.h>

#include <epan/cfile.h>
#include "capture_event.h"

/**
 * @brief Manages a capture file and its associated state and operations.
 *
 * This class serves as a Qt-friendly wrapper around the underlying core
 * capture_file struct, handling file validity, paths, events, and tapping operations.
 */
class CaptureFile : public QObject
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new CaptureFile object.
     * @param parent The parent QObject, defaults to 0.
     * @param cap_file Pointer to the underlying capture_file structure, defaults to NULL.
     */
    explicit CaptureFile(QObject *parent = 0, capture_file *cap_file = NULL);

    /**
     * @brief Destroys the CaptureFile.
     */
    ~CaptureFile();

    /**
     * @brief Retrieves the underlying capture_file pointer if valid.
     * @return Pointer to the capture_file, or NULL if invalid.
     */
    capture_file *capFile() const { return isValid() ? cap_file_ : NULL; }

    /**
     * @brief Sets the underlying capture_file pointer.
     * @param cap_file The new capture_file pointer.
     */
    void setCapFile(capture_file *cap_file) { cap_file_ = cap_file; }

    /**
     * @brief Check capture file validity
     *
     * @return true if the file is open, readable, and tappable. false if the file
     * is closed.
     */
    bool isValid() const;

    /**
     * @brief Return the full pathname.
     *
     * @return The entire pathname, converted from the native OS's encoding
     * to Unicode if necessary, or a null string if the conversion can't
     * be done.
     */
    const QString filePath();

    /**
     * @brief Return the plain filename.
     *
     * @return The last component of the pathname, including the extension,
     * converted from the native OS's encoding to Unicode if necessary, or
     * a null string if the conversion can't be done.
     */
    const QString fileName();

    /**
     * @brief Return the plain filename without an extension.
     *
     * @return The last component of the pathname, without the extension,
     * converted from the native OS's encoding to Unicode if necessary, or
     * a null string if the conversion can't be done.
     */
    const QString fileBaseName();

    /**
     * @brief Return a string representing the file suitable for use for
     *  display in the UI in places such as a main window title.
     *
     * @return One of:
     *
     *    the devices on which the capture was done, if the file is a
     *    temporary file for a capture;
     *
     *    the last component of the capture file's name, converted
     *    from the native OS's encoding to Unicode if necessary (and
     *    with REPLACEMENT CHARACTER inserted if the string can't
     *    be converted).
     *
     *    a null string, if there is no capture file.
     */
    const QString fileDisplayName();

    /**
     * @brief Return a string representing the file suitable for use in an
     *  auxiliary window title.
     *
     * @return One of:
     *
     *    the result of fileDisplayName(), if the file is open;
     *
     *    the result of fileDisplayName() followed by [closing], if
     *    the file is being closed;
     *
     *    the result of fileDisplayName() followed by [closed], if
     *    the file has been closed;
     *
     *    [no capture file], if there is no capture file.
     */
    const QString fileTitle();

    /**
     * @brief Return the current packet information.
     *
     * @return A pointer to the current packet_info struct or NULL.
     */
    struct _packet_info *packetInfo();

    /**
     * @brief Timestamp precision for the current file.
     * @return One of the WTAP_TSPREC_x values defined in wiretap/wtap.h,
     * or WTAP_TSPREC_UNKNOWN if no file is open.
     */
    int timestampPrecision();

    /**
     * @brief Reload the capture file
     */
    void reload();

    /**
     * @brief Return any set display filter
     * @return The current display filter string.
     */
    QString displayFilter() const;

    // XXX This shouldn't be needed.
    /**
     * @brief Retrieves the global capture_file instance.
     * @return Pointer to the global capture_file.
     */
    static capture_file *globalCapFile();

    /**
     * @brief Retrieves the main window associated with this capture file.
     * @return Pointer to the window.
     */
    void *window();

signals:
    /**
     * @brief Signal emitted when a capture-related event occurs.
     * @param event The capture event details.
     */
    void captureEvent(CaptureEvent event);

public slots:
    /**
     * @brief Retap the capture file. Convenience wrapper for cf_retap_packets.
     * Application events are processed periodically via update_progress_dlg.
     */
    void retapPackets();

    /**
     * @brief Retap the capture file after the current batch of application events
     * is processed. If you call this instead of retapPackets or
     * cf_retap_packets in a dialog's constructor it will be displayed before
     * tapping starts.
     */
    void delayedRetapPackets();

    /**
     * @brief Cancel any tapping that might be in progress.
     */
    void stopLoading();

    /**
     * @brief Sets the capture file's "stop_flag" member.
     *
     * @param stop_flag If true, stops the current capture file operation.
     */
    void setCaptureStopFlag(bool stop_flag = true);

private:
    /**
     * @brief Callback function for capture file events.
     * @param event The event identifier.
     * @param data Event-specific data payload.
     * @param user_data User data, typically a pointer to the CaptureFile instance.
     */
    static void captureFileCallback(int event, void *data, void *user_data);

#ifdef HAVE_LIBPCAP
    /**
     * @brief Callback function for capture session events.
     * @param event The event identifier.
     * @param cap_session Pointer to the active capture session.
     * @param user_data User data, typically a pointer to the CaptureFile instance.
     */
    static void captureCallback(int event, capture_session *cap_session, void *user_data);
#endif

    /**
     * @brief Handles a capture file event.
     * @param event The event identifier.
     * @param data Event-specific data payload.
     */
    void captureFileEvent(int event, void *data);

    /**
     * @brief Handles a capture session event.
     * @param event The event identifier.
     * @param cap_session Pointer to the active capture session.
     */
    void captureSessionEvent(int event, capture_session *cap_session);

    /**
     * @brief Retrieves the base name of the current file.
     * @return A constant reference to the file basename string.
     */
    const QString &getFileBasename();

    /** String displayed when there is no active capture file. */
    static QString no_capture_file_;

    /** Pointer to the underlying core capture_file structure. */
    capture_file *cap_file_;

    /** Current state of the file as a string for display purposes. */
    QString file_state_;
};

#endif // CAPTURE_FILE_H
