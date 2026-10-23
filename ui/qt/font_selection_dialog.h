/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_SELECTION_DIALOG_H
#define FONT_SELECTION_DIALOG_H

#include <QDialog>
#include <QFont>

#include <ui/qt/widgets/font_selection_widget.h>

namespace Ui {
class FontSelectionDialog;
}

/**
 * @brief A dialog for picking a font, built on FontSelectionWidget.
 *
 * Used instead of QFontDialog so that macOS shows the same Qt widgets as
 * the other platforms rather than the native font panel.
 */
class FontSelectionDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FontSelectionDialog.
     * @param parent The parent widget.
     */
    explicit FontSelectionDialog(QWidget *parent = nullptr);
    /** @brief Destroys the dialog and its UI form. */
    ~FontSelectionDialog();

    /**
     * @brief Set the font shown in the dialog.
     * @param font The font to show.
     */
    void setSelectedFont(const QFont &font);

    /**
     * @brief Get the font currently selected in the dialog.
     * @return The selected font.
     */
    QFont selectedFont() const;

    /**
     * @brief Choose which editing features the dialog offers.
     * @param features The features to enable.
     */
    void setFeatures(FontSelectionWidget::Features features);

    /**
     * @brief Run the dialog modally and return the chosen font.
     *
     * Mirrors QFontDialog::getFont.
     *
     * @param parent The parent widget.
     * @param initial The font shown initially.
     * @param features The editing features to offer.
     * @param ok Set to true if the user accepted the dialog and false if the
     *           user cancelled it. May be null.
     * @return The selected font if the user accepted, otherwise @p initial.
     */
    static QFont getFont(QWidget *parent, const QFont &initial,
                         FontSelectionWidget::Features features, bool *ok = nullptr);

private:
    Ui::FontSelectionDialog *ui;
};

#endif // FONT_SELECTION_DIALOG_H
