/* wireshark_dialog.h
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

#ifndef WIRESHARK_DIALOG_H
#define WIRESHARK_DIALOG_H

/*
 * @file General dialog base class
 *
 * Base class which provides convenience methods for dialogs that handle
 * capture files.
 *
 * This class attempts to destroy itself when closed. Doing this safely and
 * properly can be a bit tricky while scanning and tapping packets since
 */

// "General" is a misnomer but we already have a class named
// "CaptureFileDialog". Suggestions for a better name from
// https://code.wireshark.org/review/#/c/9739/:
// BaseCaptureDialog, CaptureHelperDialog (or rename CaptureFileDialog to something else - WiresharkFileDialog).
// TapDialog might make sense as well.

#include "capture_file.h"
#include "geometry_state_dialog.h"

class WiresharkDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    // XXX Unlike the entire QWidget API, parent is mandatory here.
    explicit WiresharkDialog(QWidget &parent, CaptureFile &capture_file);

signals:

public slots:
    /**
     * @brief Mark the start of a code block that retaps packets. If the user
     * closes the dialog while tapping, the dialog will not be destroyed until
     * endRetapPackets is called.
     *
     * This is automatically called when tapping begins, but might need to be
     * called explicilty if any member functions are called or variables are
     * accessed after tapping is finished.
     */

    void beginRetapPackets() { retap_depth_++; }
    /**
     * @brief Mark the end of a code block that retaps packets. If the user
     * has closed the dialog it will be desroyed at this point.
     *
     * This is automatically called when tapping ends, but might need to be
     * called explicilty if any member functions are called or variables are
     * accessed after tapping is finished.
     */
    virtual void endRetapPackets();

protected:
    virtual void keyPressEvent(QKeyEvent *event) { QDialog::keyPressEvent(event); }
    virtual void accept();
    virtual void reject();

    /**
     * @brief Set the window subtitle, e.g. "Foo Timeouts". The subtitle and
     * file name will be added to the dialog window title.
     * @param subtitle The subtitle to add. It should be unique, short, and
     * descriptive.
     */
    void setWindowSubtitle(const QString &subtitle);
    const QString &windowSubtitle() { return subtitle_; }
    virtual void updateWidgets();

    // Capture file and tapping
    CaptureFile &cap_file_;
    /**
     * @brief Convenience wrapper for register_tap_listener. Tap
     * listeners registered via this function are automatically
     * removed during destruction. They can also be explicitly
     * removed using remove_tap_listener or removeTapListeners.
     *
     * Shows a warning dialog if registration is unsuccessful.
     * @param tap_name A registered tap name.
     * @param tap_data A unique pointer. Usually 'this'.
     * @param filter A display filter.
     * @param flags See register_tap_listener.
     * @param tap_reset Reset callback.
     * @param tap_packet Per-packet callback.
     * @param tap_draw Draw callback.
     */
    bool registerTapListener(const char *tap_name, void *tap_data,
                        const char *filter, guint flags,
                        void (*tap_reset)(void *tapdata),
                        gboolean (*tap_packet)(void *tapdata, struct _packet_info *pinfo, struct epan_dissect *edt, const void *data),
                        void (*tap_draw)(void *tap_data));

    /**
     * @brief Remove all tap listeners registered via registerTapListener.
     */
    void removeTapListeners();

    /**
     * @brief true if the file has been closed, false otherwise.
     */
    // XXX Needs a getter?
    bool file_closed_;

    /**
     * @brief Check to see if the user has closed (and not minimized) the dialog.
     * @return true if the dialog has been closed, false otherwise.
     */
    bool dialogClosed() { return dialog_closed_; }

protected slots:
    /**
     * @brief Called when the capture file is about to close. This can be
     * used to enable or disable widgets according to the state of
     * file_closed_.
     */
    virtual void captureFileClosing();
    virtual void captureFileClosed();

private:
    void setWindowTitleFromSubtitle();

    void tryDeleteLater();

    QString subtitle_;
    QList<void *> tap_listeners_;
    int retap_depth_;
    bool dialog_closed_;

private slots:
};

#endif // WIRESHARK_DIALOG_H

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
