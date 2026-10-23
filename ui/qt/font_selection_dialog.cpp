/* font_selection_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "font_selection_dialog.h"
#include <ui_font_selection_dialog.h>

#include "main_application.h"

FontSelectionDialog::FontSelectionDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FontSelectionDialog)
{
    ui->setupUi(this);
    setWindowTitle(mainApp->windowTitleString(tr("Font")));
}

FontSelectionDialog::~FontSelectionDialog()
{
    delete ui;
}

void FontSelectionDialog::setSelectedFont(const QFont &font)
{
    ui->fontSelectionWidget->setSelectedFont(font);
}

QFont FontSelectionDialog::selectedFont() const
{
    return ui->fontSelectionWidget->selectedFont();
}

void FontSelectionDialog::setFeatures(FontSelectionWidget::Features features)
{
    ui->fontSelectionWidget->setFeatures(features);
}

QFont FontSelectionDialog::getFont(QWidget *parent, const QFont &initial,
                                   FontSelectionWidget::Features features, bool *ok)
{
    FontSelectionDialog dialog(parent);
    dialog.setFeatures(features);
    dialog.setSelectedFont(initial);
    const bool accepted = dialog.exec() == QDialog::Accepted;
    if (ok) {
        *ok = accepted;
    }
    return accepted ? dialog.selectedFont() : initial;
}
