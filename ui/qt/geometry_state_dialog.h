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
    explicit GeometryStateDialog(QWidget *parent, Qt::WindowFlags f = Qt::Window) : QDialog(parent, f) {}
#else
    explicit GeometryStateDialog(QWidget *parent, Qt::WindowFlags f = Qt::Window) : QDialog(NULL, f), parent_(parent) {}
#endif
    ~GeometryStateDialog();

#ifndef Q_OS_MAC
public:
    void setWindowModality(Qt::WindowModality windowModality);
#endif

protected:
    void loadGeometry(int width = 0, int height = 0, const QString &dialog_name = QString());
    void loadSplitterState(QSplitter *splitter = nullptr);

private:
    void saveWindowGeometry();
    void saveSplitterState(const QSplitter *splitter = nullptr);

    QString dialog_name_;
#ifndef Q_OS_MAC
    QWidget *parent_;
#endif
};

#endif // GEOMETRY_STATE_DIALOG_H
