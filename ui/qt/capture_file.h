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
#include <QEvent>

#include <config.h>

#include <glib.h>

#include "cfile.h"

typedef struct _capture_session capture_session;

struct _packet_info;

class CaptureEvent : public QObject
{
    Q_OBJECT
public:
    enum Context {
#ifdef HAVE_LIBPCAP
        Capture =  0x0001,
        Update =   0x0100 | Capture,
        Fixed =    0x0200 | Capture,
#endif
        File =     0x0002,
        Reload =   0x0100 | File,
        Rescan =   0x0200 | File,
        Save =     0x0400 | File,
        Retap =    0x0800 | File,
        Merge =    0x1000 | File
    };

    enum EventType {
        Opened      = 0x0001,
        Started     = 0x0002,
        Finished    = 0x0004,
        Closing     = 0x0008,
        Closed      = 0x0010,
        Failed      = 0x0020,
        Stopped     = 0x0040,
        Flushed     = 0x0080,
        Prepared    = 0x0100,
        Continued   = 0x0200,
        Stopping    = 0x0400
    };

    CaptureEvent(Context ctx, EventType evt);
    CaptureEvent(Context ctx, EventType evt, QString file);
    CaptureEvent(Context ctx, EventType evt, capture_session * session);

    Context captureContext() const;
    EventType eventType() const;
    QString filePath() const;
    capture_session * capSession() const;

private:
    Context _ctx;
    EventType _evt;
    QString _filePath;
    capture_session * _session;
};

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
    void captureEvent(CaptureEvent *);

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
