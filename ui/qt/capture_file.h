/* capture_file.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CAPTURE_FILE_H
#define CAPTURE_FILE_H

#include <QObject>

#include <config.h>

#include <glib.h>

typedef struct _capture_file capture_file;
typedef struct _capture_session capture_session;

struct _packet_info;

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

    /** Get the current selected row
     *
     * @return the current selected index of the packet list if the capture
     * file is open and a packet is selected, otherwise -1.
     */
    int currentRow();

    /** Return a filename suitable for use in a window title.
     *
     * @return One of: the basename of the capture file without an extension,
     *  the basename followed by "[closing]", "[closed]", or "[no capture file]".
     */
    const QString fileTitle() { return fileName() + file_state_; }

    /** Return the plain filename.
     *
     * @return The basename of the capture file without an extension.
     */
    const QString fileName();

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

    // XXX This shouldn't be needed.
    static capture_file *globalCapFile();

    gpointer window();

signals:
    void captureFileOpened() const;
    void captureFileReadStarted() const;
    void captureFileReadFinished() const;
    void captureFileReloadStarted() const;
    void captureFileReloadFinished() const;
    void captureFileRescanStarted() const;
    void captureFileRescanFinished() const;
    void captureFileRetapStarted() const;
    void captureFileRetapFinished() const;
    void captureFileClosing() const;
    void captureFileClosed() const;
    void captureFileSaveStarted(const QString &file_path) const;
    void captureFileSaveFinished() const;
    void captureFileSaveFailed() const;
    void captureFileSaveStopped() const;
    void captureFileFlushTapsData() const;

    void captureCapturePrepared(capture_session *cap_session);
    void captureCaptureUpdateStarted(capture_session *cap_session);
    void captureCaptureUpdateContinue(capture_session *cap_session);
    void captureCaptureUpdateFinished(capture_session *cap_session);
    void captureCaptureFixedStarted(capture_session *cap_session);
    void captureCaptureFixedContinue(capture_session *cap_session);
    void captureCaptureFixedFinished(capture_session *cap_session);
    void captureCaptureStopping(capture_session *cap_session);
    void captureCaptureFailed(capture_session *cap_session);

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
    void captureEvent(int event, capture_session *cap_session);
    const QString &getFileBasename();

    static QString no_capture_file_;

    capture_file *cap_file_;
    QString file_name_;
    QString file_state_;
};

#endif // CAPTURE_FILE_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
