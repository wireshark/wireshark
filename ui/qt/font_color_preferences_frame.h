/* font_color_preferences_frame.h
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

#ifndef FONT_COLOR_PREFERENCES_FRAME_H
#define FONT_COLOR_PREFERENCES_FRAME_H

#include "preferences_dialog.h"

#include <QFrame>
#include <QFont>

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
    pref_t *pref_marked_fg_;
    pref_t *pref_marked_bg_;
    pref_t *pref_ignored_fg_;
    pref_t *pref_ignored_bg_;
    pref_t *pref_client_fg_;
    pref_t *pref_client_bg_;
    pref_t *pref_server_fg_;
    pref_t *pref_server_bg_;
    pref_t *pref_valid_fg_;
    pref_t *pref_valid_bg_;
    pref_t *pref_invalid_fg_;
    pref_t *pref_invalid_bg_;
    pref_t *pref_deprecated_fg_;
    pref_t *pref_deprecated_bg_;
    QFont cur_font_;

    void updateWidgets();
    void changeColor(pref_t *pref);

private slots:
    void on_fontPushButton_clicked();

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
