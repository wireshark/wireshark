/* font_color_preferences_frame.cpp
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

#include "qt_ui_utils.h"

#include "font_color_preferences_frame.h"
#include <ui_font_color_preferences_frame.h>
#include "color_utils.h"
#include "wireshark_application.h"

#include <QFontDialog>
#include <QColorDialog>

#include <epan/prefs-int.h>

static const char *font_pangrams_[] = { //TODO : Fix translate
  "Example GIF query packets have jumbo window sizes",
  "Lazy badgers move unique waxy jellyfish packets"
};
const int num_font_pangrams_ = (sizeof font_pangrams_ / sizeof font_pangrams_[0]);

FontColorPreferencesFrame::FontColorPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::FontColorPreferencesFrame)
{
    ui->setupUi(this);

    pref_qt_gui_font_name_ = prefFromPrefPtr(&prefs.gui_qt_font_name);
    pref_marked_fg_ = prefFromPrefPtr(&prefs.gui_marked_fg);
    pref_marked_bg_ = prefFromPrefPtr(&prefs.gui_marked_bg);
    pref_ignored_fg_ = prefFromPrefPtr(&prefs.gui_ignored_fg);
    pref_ignored_bg_ = prefFromPrefPtr(&prefs.gui_ignored_bg);
    pref_client_fg_ = prefFromPrefPtr(&prefs.st_client_fg);
    pref_client_bg_ = prefFromPrefPtr(&prefs.st_client_bg);
    pref_server_fg_ = prefFromPrefPtr(&prefs.st_server_fg);
    pref_server_bg_ = prefFromPrefPtr(&prefs.st_server_bg);
    pref_valid_bg_ = prefFromPrefPtr(&prefs.gui_text_valid);
    pref_invalid_bg_ = prefFromPrefPtr(&prefs.gui_text_invalid);
    pref_deprecated_bg_ = prefFromPrefPtr(&prefs.gui_text_deprecated);

    cur_font_.fromString(pref_qt_gui_font_name_->stashed_val.string);

}

FontColorPreferencesFrame::~FontColorPreferencesFrame()
{
    delete ui;
}

void FontColorPreferencesFrame::showEvent(QShowEvent *)
{
    GRand *rand_state = g_rand_new();
    QString pangram = QString(font_pangrams_[g_rand_int_range(rand_state, 0, num_font_pangrams_)]) + " 0123456789";
    ui->fontSampleLineEdit->setText(pangram);
    ui->fontSampleLineEdit->setCursorPosition(0);
    ui->fontSampleLineEdit->setMinimumWidth(wsApp->monospaceTextSize(pangram.toUtf8().constData()) + wsApp->monospaceTextSize(" "));
    g_rand_free(rand_state);

    updateWidgets();
}

void FontColorPreferencesFrame::updateWidgets()
{
    int margin = style()->pixelMetric(QStyle::PM_LayoutLeftMargin);

#if QT_VERSION < QT_VERSION_CHECK(4, 8, 0)
    ui->fontPushButton->setText(
                cur_font_.family() + " " +
                QString::number(cur_font_.pointSizeF(), 'f', 1));
#else
    ui->fontPushButton->setText(
                cur_font_.family() + " " + cur_font_.styleName() + " " +
                QString::number(cur_font_.pointSizeF(), 'f', 1));
#endif
    ui->fontSampleLineEdit->setFont(cur_font_);

    QString line_edit_ss = QString("QLineEdit { margin-left: %1px; }").arg(margin);
    ui->fontSampleLineEdit->setStyleSheet(line_edit_ss);

    QString color_button_ss =
            "QPushButton {"
            "  border: 1px solid palette(Dark);"
            "  background-color: %1;"
            "  margin-left: %2px;"
            "}";
    QString sample_text_ss =
            "QLineEdit {"
            "  color: %1;"
            "  background-color: %2;"
            "}";

    ui->markedFGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_marked_fg_->stashed_val.color).name())
                                          .arg(margin));
    ui->markedBGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_marked_bg_->stashed_val.color).name())
                                          .arg(0));
    ui->markedSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                ColorUtils::fromColorT(&pref_marked_fg_->stashed_val.color).name(),
                                                ColorUtils::fromColorT(&pref_marked_bg_->stashed_val.color).name()));
    ui->markedSampleLineEdit->setFont(cur_font_);

    ui->ignoredFGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_ignored_fg_->stashed_val.color).name())
                                           .arg(margin));
    ui->ignoredBGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_ignored_bg_->stashed_val.color).name())
                                           .arg(0));
    ui->ignoredSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                ColorUtils::fromColorT(&pref_ignored_fg_->stashed_val.color).name(),
                                                ColorUtils::fromColorT(&pref_ignored_bg_->stashed_val.color).name()));
    ui->ignoredSampleLineEdit->setFont(cur_font_);

    ui->clientFGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_client_fg_->stashed_val.color).name())
                                          .arg(margin));
    ui->clientBGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_client_bg_->stashed_val.color).name())
                                          .arg(0));
    ui->clientSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                ColorUtils::fromColorT(&pref_client_fg_->stashed_val.color).name(),
                                                ColorUtils::fromColorT(&pref_client_bg_->stashed_val.color).name()));
    ui->clientSampleLineEdit->setFont(cur_font_);

    ui->serverFGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_server_fg_->stashed_val.color).name())
                                          .arg(margin));
    ui->serverBGPushButton->setStyleSheet(color_button_ss.arg(
                                              ColorUtils::fromColorT(&pref_server_bg_->stashed_val.color).name())
                                          .arg(0));
    ui->serverSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                ColorUtils::fromColorT(&pref_server_fg_->stashed_val.color).name(),
                                                ColorUtils::fromColorT(&pref_server_bg_->stashed_val.color).name()));
    ui->serverSampleLineEdit->setFont(cur_font_);

    ui->validFilterBGPushButton->setStyleSheet(color_button_ss.arg(
                                                   ColorUtils::fromColorT(&pref_valid_bg_->stashed_val.color).name())
                                               .arg(0));
    ui->validFilterSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                     "palette(text)",
                                                     ColorUtils::fromColorT(&pref_valid_bg_->stashed_val.color).name()));
    ui->invalidFilterBGPushButton->setStyleSheet(color_button_ss.arg(
                                                     ColorUtils::fromColorT(&pref_invalid_bg_->stashed_val.color).name())
                                                 .arg(0));
    ui->invalidFilterSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                       "palette(text)",
                                                       ColorUtils::fromColorT(&pref_invalid_bg_->stashed_val.color).name()));
    ui->deprecatedFilterBGPushButton->setStyleSheet(color_button_ss.arg(
                                                        ColorUtils::fromColorT(&pref_deprecated_bg_->stashed_val.color).name())
                                                    .arg(0));
    ui->deprecatedFilterSampleLineEdit->setStyleSheet(sample_text_ss.arg(
                                                          "palette(text)",
                                                          ColorUtils::fromColorT(&pref_deprecated_bg_->stashed_val.color).name()));
}

void FontColorPreferencesFrame::changeColor(pref_t *pref)
{
    QColorDialog color_dlg;

    color_dlg.setCurrentColor(QColor(
                                  pref->stashed_val.color.red >> 8,
                                  pref->stashed_val.color.green >> 8,
                                  pref->stashed_val.color.blue >> 8
                                  ));
    if (color_dlg.exec() == QDialog::Accepted) {
        QColor cc = color_dlg.currentColor();
        pref->stashed_val.color.red = cc.red() << 8 | cc.red();
        pref->stashed_val.color.green = cc.green() << 8 | cc.green();
        pref->stashed_val.color.blue = cc.blue() << 8 | cc.blue();
        updateWidgets();
    }
}

void FontColorPreferencesFrame::on_fontPushButton_clicked()
{
    bool ok;
    QFont new_font = QFontDialog::getFont(&ok, cur_font_, this, wsApp->windowTitleString(tr("Font")));
    if (ok) {
        g_free(pref_qt_gui_font_name_->stashed_val.string);
        pref_qt_gui_font_name_->stashed_val.string = qstring_strdup(new_font.toString());
        cur_font_ = new_font;
        updateWidgets();
    }
}

void FontColorPreferencesFrame::on_markedFGPushButton_clicked()
{
    changeColor(pref_marked_fg_);
}

void FontColorPreferencesFrame::on_markedBGPushButton_clicked()
{
    changeColor(pref_marked_bg_);
}

void FontColorPreferencesFrame::on_ignoredFGPushButton_clicked()
{
    changeColor(pref_ignored_fg_);
}

void FontColorPreferencesFrame::on_ignoredBGPushButton_clicked()
{
    changeColor(pref_ignored_bg_);
}

void FontColorPreferencesFrame::on_clientFGPushButton_clicked()
{
    changeColor(pref_client_fg_);
}

void FontColorPreferencesFrame::on_clientBGPushButton_clicked()
{
    changeColor(pref_client_bg_);
}

void FontColorPreferencesFrame::on_serverFGPushButton_clicked()
{
    changeColor(pref_server_fg_);
}

void FontColorPreferencesFrame::on_serverBGPushButton_clicked()
{
    changeColor(pref_server_bg_);
}

void FontColorPreferencesFrame::on_validFilterBGPushButton_clicked()
{
    changeColor(pref_valid_bg_);
}

void FontColorPreferencesFrame::on_invalidFilterBGPushButton_clicked()
{
    changeColor(pref_invalid_bg_);
}

void FontColorPreferencesFrame::on_deprecatedFilterBGPushButton_clicked()
{
    changeColor(pref_deprecated_bg_);
}

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
