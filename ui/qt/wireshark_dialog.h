/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <epan/tap.h>

#include "capture_file.h"
#include "geometry_state_dialog.h"

/**
 * @brief Base class for Wireshark specific dialogs that require interaction with a CaptureFile.
 */
class WiresharkDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    // XXX Unlike the entire QWidget API, parent is mandatory here.
    /**
     * @brief Constructs a new WiresharkDialog object.
     * @param parent The parent widget.
     * @param capture_file The associated capture file.
     */
    explicit WiresharkDialog(QWidget &parent, CaptureFile &capture_file);

    /**
     * @brief Checks if the capture file has been closed.
     * @return true if the file has been closed, false otherwise.
     */
    bool fileClosed() const { return file_closed_; }

protected:
    /**
     * @brief Handles key press events.
     * @param event The key press event.
     */
    virtual void keyPressEvent(QKeyEvent *event) override { QDialog::keyPressEvent(event); }

    /**
     * @brief Accepts the dialog.
     */
    virtual void accept() override;

    /**
     * @brief Rejects the dialog.
     */
    virtual void reject() override;

    /**
     * @brief Mark the start of a code block that retaps packets. If the user
     * closes the dialog while tapping, the dialog will not be destroyed until
     * endRetapPackets is called.
     *
     * This is automatically called when tapping begins, but might need to be
     * called explicitly if any member functions are called or variables are
     * accessed after tapping is finished.
     */
    virtual void beginRetapPackets();

    /**
     * @brief Mark the end of a code block that retaps packets. If the user
     * has closed the dialog it will be destroyed at this point.
     *
     * This is automatically called when tapping ends, but might need to be
     * called explicitly if any member functions are called or variables are
     * accessed after tapping is finished.
     */
    virtual void endRetapPackets();

    /**
     * @brief Set the window subtitle, e.g. "Foo Timeouts". The subtitle and
     * file name will be added to the dialog window title.
     * @param subtitle The subtitle to add. It should be unique, short, and
     * descriptive.
     */
    void setWindowSubtitle(const QString &subtitle);

    /**
     * @brief Retrieves the current window subtitle.
     * @return The window subtitle string.
     */
    const QString &windowSubtitle() { return subtitle_; }

    /**
     * @brief Updates the state and contents of the dialog's widgets.
     */
    virtual void updateWidgets();

    // Capture file and tapping
    /** @brief Reference to the underlying capture file. */
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
     * @return True if registration was successful, false otherwise.
     */
    bool registerTapListener(const char *tap_name, void *tap_data,
                        const char *filter, unsigned flags,
                        tap_reset_cb tap_reset,
                        tap_packet_cb tap_packet,
                        tap_draw_cb tap_draw);

    /**
     * @brief Remove all tap listeners registered via registerTapListener.
     */
    virtual void removeTapListeners();

    // XXX - Move this to private, have subclasses use the getter?
    /** @brief Flag indicating if the capture file has been closed. */
    bool file_closed_;

    bool listening() const { return !tap_listeners_.isEmpty(); }

    /**
     * @brief Check to see if the user has closed (and not minimized) the dialog.
     * @return true if the dialog has been closed, false otherwise.
     */
    bool dialogClosed() const { return dialog_closed_; }

    /**
     * @brief Check to see if we're currently retapping. If this is positive,
     * tapping will fail in process_specified_records.
     * @return The current retap depth. (In current implementation, 0 or 1.)
     */
    int retapDepth() const { return retap_depth_; }

    /**
     * @brief Called when the capture file is about to close. This can be
     * used to disconnect taps and similar actions.
     * updateWidgets() is called at the end.
     * To enable/disable widgets captureFileClosed() is more suitable.
     */
    virtual void captureFileClosing();

    /**
     * @brief Called when the capture file was closed. This can be
     * used to enable or disable widgets according to the state of
     * file_closed_.
     * updateWidgets() is called at the end.
     */
    virtual void captureFileClosed();

protected slots:
    /**
     * @brief Handles capture events.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

private:
    /**
     * @brief Cleans up dialog resources, optionally closing the dialog.
     * @param closeDialog True to also close the dialog window.
     */
    void dialogCleanup(bool closeDialog = false);

    /** @brief The dialog's subtitle string. */
    QString subtitle_;

    /** @brief List of registered tap listener data pointers. */
    QList<void *> tap_listeners_;

    /** @brief The current depth of nested retap operations. */
    int retap_depth_;

    /** @brief Flag indicating if the dialog has been closed by the user. */
    bool dialog_closed_;

private slots:
};

#endif // WIRESHARK_DIALOG_H
