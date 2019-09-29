/* font_color_preferences_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_COLOR_PREFERENCES_FRAME_H
#define FONT_COLOR_PREFERENCES_FRAME_H

#include <QFrame>
#include <QFont>

#include <epan/prefs.h>

namespace Ui {
class FontColorPreferencesFrame;
}

class FontColorPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit FontColorPreferencesFrame(QWidget *parent = 0);
    ~FontColorPreferencesFrame();

protected:
    void showEvent(QShowEvent *evt);

private:
    Ui::FontColorPreferencesFrame *ui;

    pref_t *pref_qt_gui_font_name_;
    pref_t *pref_active_fg_;
    pref_t *pref_active_bg_;
    pref_t *pref_active_style_;
    pref_t *pref_inactive_fg_;
    pref_t *pref_inactive_bg_;
    pref_t *pref_inactive_style_;
    pref_t *pref_marked_fg_;
    pref_t *pref_marked_bg_;
    pref_t *pref_ignored_fg_;
    pref_t *pref_ignored_bg_;
    pref_t *pref_client_fg_;
    pref_t *pref_client_bg_;
    pref_t *pref_server_fg_;
    pref_t *pref_server_bg_;
    pref_t *pref_valid_bg_;
    pref_t *pref_invalid_bg_;
    pref_t *pref_deprecated_bg_;
    QFont cur_font_;

    void updateWidgets();
    void changeColor(pref_t *pref);

private slots:
    void colorChanged(pref_t *pref, const QColor &cc);
    void on_fontPushButton_clicked();

    void on_activeFGPushButton_clicked();
    void on_activeBGPushButton_clicked();
    void on_activeStyleComboBox_currentIndexChanged(int index);
    void on_inactiveFGPushButton_clicked();
    void on_inactiveBGPushButton_clicked();
    void on_inactiveStyleComboBox_currentIndexChanged(int index);
    void on_markedFGPushButton_clicked();
    void on_markedBGPushButton_clicked();
    void on_ignoredFGPushButton_clicked();
    void on_ignoredBGPushButton_clicked();
    void on_clientFGPushButton_clicked();
    void on_clientBGPushButton_clicked();
    void on_serverFGPushButton_clicked();
    void on_serverBGPushButton_clicked();
    void on_validFilterBGPushButton_clicked();
    void on_invalidFilterBGPushButton_clicked();
    void on_deprecatedFilterBGPushButton_clicked();
};

#endif // FONT_COLOR_PREFERENCES_FRAME_H
