/* font_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include "font_preferences_frame.h"
#include <ui_font_preferences_frame.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/utils/font_manager.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include <QFont>
#include <QFontInfo>

FontPreferencesFrame::FontPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::FontPreferencesFrame)
{
    ui->setupUi(this);

    pref_qt_gui_font_name_ = prefFromPrefPtr(&prefs.gui_font_name);
    const QFont font = FontManager::fontFromName(
        QString::fromUtf8(prefs_get_string_value(pref_qt_gui_font_name_, pref_stashed)));

    ui->fontSelectionWidget->setFontClass(FontSelectionWidget::FontClass::Monospace);
    ui->fontSelectionWidget->setSelectedFont(font);
    // A stored proportional family must stay visible and selected, so the
    // monospace filter starts off for it.
    ui->fontSelectionWidget->setFamilyFilter(
        QFontInfo(ui->fontSelectionWidget->resolvedFont()).fixedPitch()
            ? FontSelectionWidget::FamilyFilter::FixedPitchOnly
            : FontSelectionWidget::FamilyFilter::AllFamilies);

    connect(ui->fontSelectionWidget, &FontSelectionWidget::changed,
            this, &FontPreferencesFrame::fontChanged);

    // Section title and hints share their styling with the Theme page.
    // Done after all children exist.
    set_section_title_font(ui->fontGroupBox);
    set_hint_label_style(ui->proportionalHintLabel);
    set_hint_label_style(ui->markerHintLabel);

    updateHints();
}

FontPreferencesFrame::~FontPreferencesFrame()
{
    delete ui;
}

void FontPreferencesFrame::updateHints()
{
    const QFont resolved = ui->fontSelectionWidget->resolvedFont();
    const QFontInfo info(resolved);

    ui->proportionalHintLabel->setText(
        tr("%1 is not a monospaced font. Hex bytes and aligned columns will not line up.")
            .arg(ui->fontSelectionWidget->selectedFont().family()));
    ui->proportionalHintLabel->setVisible(!info.fixedPitch());

    ui->markerHintLabel->setText(
        tr("Packet Details underlines links and shows entries of disabled coloring rules in italic. "
           "With an italic or underlined font only their colors mark them."));
    ui->markerHintLabel->setVisible(info.style() != QFont::StyleNormal || resolved.underline());
}

void FontPreferencesFrame::fontChanged()
{
    prefs_set_string_value(pref_qt_gui_font_name_,
                           ui->fontSelectionWidget->selectedFont().toString().toUtf8().constData(),
                           pref_stashed);
    updateHints();
}
