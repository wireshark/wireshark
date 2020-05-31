/* geometry_state_dialog.h
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

class GeometryStateDialog : public QDialog
{
    Q_OBJECT

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
// on macOS: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12544
//
// Pass in the parent on macOS and NULL elsewhere so that we have an
// independent window that un-maximizes correctly.

#ifdef Q_OS_MAC
    explicit GeometryStateDialog(QWidget *parent, Qt::WindowFlags f = Qt::WindowFlags()) : QDialog(parent, f) {}
#else
    explicit GeometryStateDialog(QWidget *, Qt::WindowFlags f = Qt::WindowFlags()) : QDialog(NULL, f) {}
#endif
    ~GeometryStateDialog();

protected:
    void loadGeometry(int width = 0, int height = 0, const QString &dialog_name = QString());

private:
    void saveGeometry();

    QString dialog_name_;
};

#endif // GEOMETRY_STATE_DIALOG_H

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
