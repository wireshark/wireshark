/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GEOMETRY_STATE_DIALOG_H
#define GEOMETRY_STATE_DIALOG_H

#include <QDialog>
#include <QSplitter>

/**
 * @brief A dialog that remembers its geometry and splitter state.
 */
class GeometryStateDialog : public QDialog
{
public:

// As discussed in change 7072, QDialogs have different minimize and "on
// top" behaviors depending on their parents, flags, and platforms.
//
// W = Windows, L = Linux (and other non-macOS UN*Xes), X = macOS
//
// QDialog(parent)
//
//   W,L: Always on top, no minimize button.
//   X: Independent, no minimize button.
//
// QDialog(parent, Qt::Window)
//
//   W: Always on top, minimize button. Minimizes to a small title bar
//      attached to the taskbar and not the taskbar itself. (The GTK+
//      UI used to do this.)
//   L: Always on top, minimize button.
//   X: Independent, minimize button.
//
// QDialog(NULL)
//
//   W, L, X: Independent, no minimize button.
//
// QDialog(NULL, Qt::Window)
//
//   W, L, X: Independent, minimize button.
//
// Additionally, maximized, parent-less dialogs can close to a black screen
// on macOS: https://gitlab.com/wireshark/wireshark/-/issues/12544
// (aka https://bugreports.qt.io/browse/QTBUG-46701 ), which claims to
// be fixed in Qt 6.2.0
//
// Pass in the parent on macOS and NULL elsewhere so that we have an
// independent window that un-maximizes correctly.
//
// Pass Qt::Window as the flags that we have minimize and maximize buttons, as
// this class is for dialogs where we want to remember user-set geometry.
// (We're still at the mercy of the platform and Qt, e.g. recent GNOME defaults
// to not having min or max buttons, instead requiring right-clicking on the
// menu title bar to perform the minimize or maximize actions. We can't do
// anything about that, though users can.)
//
// However, we want modal dialogs to always be on top of their parent.
// On Linux with Mutter (and maybe some other window managers), an orphan
// ApplicationModal dialog is not always on top, and it's confusing if a
// modal dialog is behind other windows it blocks (Issue #19099). On Windows,
// a modal orphan dialog is always on top, but setting the parent adds effects
// like causing the modal dialog to shake if the blocked parent is clicked.
// So when setting the dialog modal, set the parent if we haven't yet.

#ifdef Q_OS_MAC
    /**
     * @brief Constructs a new GeometryStateDialog with the specified parent and window flags.
     * @param parent The parent widget for the dialog.
     * @param f The window flags for the dialog, defaulting to Qt::Window.
     * On macOS, the parent is set to ensure the dialog behaves as an independent window that un-maximizes correctly.
     * On other platforms, the parent is set to NULL to allow for independent window behavior.
     * The Qt::Window flag is used to provide minimize and maximize buttons, as this dialog is intended to remember user-set geometry.
     */
    explicit GeometryStateDialog(QWidget *parent, Qt::WindowFlags f = Qt::Window) : QDialog(parent, f) {}
#else
    /**
     * @brief Constructs a new GeometryStateDialog with the specified parent and window flags.
     * @param parent The parent widget for the dialog.
     * @param f The window flags for the dialog, defaulting to Qt::Window.
     * On macOS, the parent is set to ensure the dialog behaves as an independent window that un-maximizes correctly.
     * On other platforms, the parent is set to NULL to allow for independent window behavior.
     * The Qt::Window flag is used to provide minimize and maximize buttons, as this dialog is intended to remember user-set geometry.
     */
    explicit GeometryStateDialog(QWidget *parent, Qt::WindowFlags f = Qt::Window) : QDialog(NULL, f), parent_(parent) {}
#endif
    /**
     * @brief Save the geometry and splitter state and then destroy the GeometryStateDialog.
     */
    ~GeometryStateDialog();

#ifndef Q_OS_MAC
public:
    /**
     * @brief Sets the window modality for the dialog. On non-macOS platforms, this also sets the parent to ensure modal dialogs are always on top of their parent.
     * @param windowModality The desired window modality (e.g., Qt::ApplicationModal, Qt::WindowModal, Qt::NonModal).
     */
    void setWindowModality(Qt::WindowModality windowModality);
#endif

protected:
    /**
     * @brief Loads the geometry and splitter state for the dialog.
     * @param width The initial width for the dialog.
     * @param height The initial height for the dialog.
     * @param dialog_name The name of the dialog for saving/loading geometry.
     */
    void loadGeometry(int width = 0, int height = 0, const QString &dialog_name = QString());
    /**
     * @brief Loads the state of a splitter for the dialog.
     * @param splitter The splitter for which to load the state.
     */
    void loadSplitterState(QSplitter *splitter = nullptr);

private:
    /**
     * @brief Saves the window geometry.
     */
    void saveWindowGeometry();
    /**
     * @brief Saves the splitter state.
     * @param splitter The splitter for which to save the state.
     */
    void saveSplitterState(const QSplitter *splitter = nullptr);

    /** The name of the dialog for saving/loading geometry. */
    QString dialog_name_;
#ifndef Q_OS_MAC
    QWidget *parent_;
#endif
};

#endif // GEOMETRY_STATE_DIALOG_H
