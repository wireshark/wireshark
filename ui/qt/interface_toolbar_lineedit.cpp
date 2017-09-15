/* interface_toolbar_lineedit.cpp
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

#include "config.h"

#include "interface_toolbar_lineedit.h"
#include "stock_icon_tool_button.h"
#include "epan/prefs.h"
#include "color_utils.h"

#include <QStyle>

// To do:
// - Make a narrower apply button

InterfaceToolbarLineEdit::InterfaceToolbarLineEdit(QWidget *parent, QString validation_regex, bool is_required) :
    QLineEdit(parent),
    regex_expr_(validation_regex),
    is_required_(is_required),
    text_edited_(false)
{
    apply_button_ = new StockIconToolButton(this, "x-filter-apply");
    apply_button_->setCursor(Qt::ArrowCursor);
    apply_button_->setEnabled(false);
    apply_button_->setToolTip(tr("Apply changes"));
    apply_button_->setIconSize(QSize(24, 14));
    apply_button_->setStyleSheet(
            "QToolButton {"
            "  border: none;"
            "  background: transparent;" // Disables platform style on Windows.
            "  padding: 0 0 0 0;"
            "}"
            );

    updateStyleSheet(isValid());

    connect(this, SIGNAL(textChanged(const QString &)), this, SLOT(validateText()));
    connect(this, SIGNAL(textEdited(const QString &)), this, SLOT(validateEditedText()));
    connect(this, SIGNAL(returnPressed()), this, SLOT(applyEditedText()));
    connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyEditedText()));
}

void InterfaceToolbarLineEdit::validateText()
{
    bool valid = isValid();

    apply_button_->setEnabled(valid);
    updateStyleSheet(valid);
}

void InterfaceToolbarLineEdit::validateEditedText()
{
    text_edited_ = true;
}

void InterfaceToolbarLineEdit::applyEditedText()
{
    if (text_edited_ && isValid())
    {
        emit editedTextApplied();
        disableApplyButton();
    }
}

void InterfaceToolbarLineEdit::disableApplyButton()
{
    apply_button_->setEnabled(false);
    text_edited_ = false;
}

bool InterfaceToolbarLineEdit::isValid()
{
    bool valid = true;

    if (is_required_ && text().length() == 0)
    {
        valid = false;
    }

    if (!regex_expr_.isEmpty() && text().length() > 0)
    {
        if (!regex_expr_.isValid() || regex_expr_.indexIn(text(), 0) == -1)
        {
            valid = false;
        }
    }

    return valid;
}

void InterfaceToolbarLineEdit::updateStyleSheet(bool is_valid)
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize apsz = apply_button_->sizeHint();

    QString style_sheet = QString(
            "InterfaceToolbarLineEdit {"
            "  padding-right: %1px;"
            "  background-color: %2;"
            "}"
            )
            .arg(apsz.width() + frameWidth)
            .arg(is_valid || !isEnabled() ? QString("") : ColorUtils::fromColorT(prefs.gui_text_invalid).name());

    setStyleSheet(style_sheet);
}

void InterfaceToolbarLineEdit::resizeEvent(QResizeEvent *)
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize apsz = apply_button_->sizeHint();

    apply_button_->move(contentsRect().right() - frameWidth - apsz.width() + 2,
                        contentsRect().top());
    apply_button_->setMinimumHeight(contentsRect().height());
    apply_button_->setMaximumHeight(contentsRect().height());
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
