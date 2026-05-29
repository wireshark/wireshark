/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_DEBUG_DIALOG_H
#define THEME_DEBUG_DIALOG_H

#include <ui/qt/geometry_state_dialog.h>

#include <QPointer>

class QCheckBox;
class QLabel;
class QPlainTextEdit;
class QTableWidget;
class QTimer;

/**
 * Internals dialog for inspecting the active theme and live widget
 * geometry.  Stays open while the user interacts with the main
 * window; polls QApplication::widgetAt() so the widget readout tracks
 * the cursor without installing a global event filter.
 */
class ThemeDebugDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ThemeDebugDialog(QWidget *parent = nullptr);
    ~ThemeDebugDialog();

private slots:
    void refresh();
    void pollWidgetUnderCursor();

protected:
    // Watches the application for Alt+Shift+click to pin the inspector on the
    // clicked widget (and stop cursor tracking).
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void buildUi();
    void populateTokens();
    void populateWidgetPalette(QWidget *w);
    void displayWidget(QWidget *w);
    void updateThemeSection();
    void updateMainWindowSection();

    QPointer<QWidget> main_window_;
    QPointer<QWidget> tracked_;

    QLabel *theme_name_;
    QLabel *theme_internal_;
    QLabel *theme_version_;
    QLabel *theme_author_;
    QLabel *theme_description_;
    QLabel *theme_mode_;
    QLabel *theme_dark_;

    QLabel *mw_geometry_;
    QLabel *mw_frame_;
    QLabel *mw_screen_;
    QLabel *mw_dpi_;
    QLabel *mw_state_;

    QCheckBox *track_widgets_;
    QLabel *cursor_pos_;
    QLabel *widget_class_;
    QLabel *widget_name_;
    QLabel *widget_font_;
    QLabel *widget_geometry_;
    QLabel *widget_global_;
    QLabel *widget_parents_;
    QPlainTextEdit *widget_stylesheet_;
    QTableWidget *widget_palette_;

    QTableWidget *token_table_;
    QTimer *poll_timer_;
};

#endif // THEME_DEBUG_DIALOG_H
