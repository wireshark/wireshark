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

#include <glib.h>

#include "cfile.h"
#include "capture_event.h"

class CaptureFile : public QObject
{
    Q_OBJECT
public:
    explicit CaptureFile(QObject *parent = 0, capture_file *cap_file = NULL);
    ~CaptureFile();

    capture_file *capFile() const { return isValid() ? cap_file_ : NULL; }
    void setCapFile(capture_file *cap_file) { cap_file_ = cap_file; }

    /** Check capture file validity
     *
     * @return true if the file is open, readable, and tappable. false if the file
     * is closed.
     */
    bool isValid() const;

    /** Return the full pathname.
     *
     * @return The entire pathname, converted from the native OS's encoding
     * to Unicode if necessary, or a null string if the conversion can't
     * be done.
     */
    const QString filePath();

    /** Return the plain filename.
     *
     * @return The last component of the pathname, including the extension,
     * converted from the native OS's encoding to Unicode if necessary, or
     * a null string if the conversion can't be done.
     */
    const QString fileName();

    /** Return the plain filename without an extension.
     *
     * @return The last component of the pathname, without the extension,
     * converted from the native OS's encoding to Unicode if necessary, or
     * a null string if the conversion can't be done.
     */
    const QString fileBaseName();

    /** Return a string representing the file suitable for use for
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

    /** Return a string representing the file suitable for use in an
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

    /** Return the current packet information.
     *
     * @return A pointer to the current packet_info struct or NULL.
     */
    struct _packet_info *packetInfo();

    /** Timestamp precision for the current file.
     * @return One of the WTAP_TSPREC_x values defined in wiretap/wtap.h,
     * or WTAP_TSPREC_UNKNOWN if no file is open.
     */
    int timestampPrecision();

    /** Reload the capture file
     */
    void reload();

    /** Return any set display filter
     */
    QString displayFilter() const;

    // XXX This shouldn't be needed.
    static capture_file *globalCapFile();

    gpointer window();

signals:
    void captureEvent(CaptureEvent);

public slots:
    /** Retap the capture file. Convenience wrapper for cf_retap_packets.
     * Application events are processed periodically via update_progress_dlg.
     */
    void retapPackets();

    /** Retap the capture file after the current batch of application events
     * is processed. If you call this instead of retapPackets or
     * cf_retap_packets in a dialog's constructor it will be displayed before
     * tapping starts.
     */
    void delayedRetapPackets();

    /** Cancel any tapping that might be in progress.
     */
    void stopLoading();

    /** Sets the capture file's "stop_flag" member.
     *
     * @param stop_flag If true, stops the current capture file operation.
     */
    void setCaptureStopFlag(bool stop_flag = true);

private:
    static void captureFileCallback(gint event, gpointer data, gpointer user_data);
#ifdef HAVE_LIBPCAP
    static void captureCallback(gint event, capture_session *cap_session, gpointer user_data);
#endif

    void captureFileEvent(int event, gpointer data);
    void captureSessionEvent(int event, capture_session *cap_session);
    const QString &getFileBasename();

    static QString no_capture_file_;

    capture_file *cap_file_;
    QString file_state_;
};

#endif // CAPTURE_FILE_H
