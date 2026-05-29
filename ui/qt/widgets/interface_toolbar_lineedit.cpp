/* interface_toolbar_lineedit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/interface_toolbar_lineedit.h>
#include <ui/qt/widgets/stock_icon_tool_button.h>
#include <ui/qt/utils/theme_manager.h>

#include <QStyle>

// To do:
// - Make a narrower apply button

InterfaceToolbarLineEdit::InterfaceToolbarLineEdit(QWidget *parent, QString validation_regex, bool is_required) :
    QLineEdit(parent),
    regex_expr_(validation_regex, QRegularExpression::UseUnicodePropertiesOption),
    is_required_(is_required),
    text_edited_(false)
{
    apply_button_ = new StockIconToolButton(this, "x-filter-apply");
    apply_button_->setCursor(Qt::ArrowCursor);
    apply_button_->setEnabled(false);
    apply_button_->setToolTip(tr("Apply changes"));
    apply_button_->setIconSize(QSize(24, 14));

    updateStyleSheet(isValid());

    connect(this, &InterfaceToolbarLineEdit::textChanged, this, &InterfaceToolbarLineEdit::validateText);
    connect(this, &InterfaceToolbarLineEdit::textEdited, this, &InterfaceToolbarLineEdit::validateEditedText);
    connect(this, &InterfaceToolbarLineEdit::returnPressed, this, &InterfaceToolbarLineEdit::applyEditedText);
    connect(apply_button_, &StockIconToolButton::clicked, this, &InterfaceToolbarLineEdit::applyEditedText);
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this]() {
        updateStyleSheet(isValid());
    });
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

    if (!regex_expr_.pattern().isEmpty() && text().length() > 0)
    {
        if (!regex_expr_.isValid() || !regex_expr_.match(text()).hasMatch())
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

    QString style_sheet =
            ThemeManager::styleSheet(QStringLiteral("widgets/interface-toolbar-lineedit"));

    style_sheet += QStringLiteral(
            "InterfaceToolbarLineEdit {"
            "  padding-right: %1px;"
            "}"
            )
            .arg(apsz.width() + frameWidth);

#ifdef Q_OS_MAC
    style_sheet += QStringLiteral(
            "InterfaceToolbarLineEdit {"
            "  border: 1px solid palette(shadow);"
            "  border-radius: 3px;"
            "}"
            );
#endif

    setStyleSheet(style_sheet);
    ThemeManager::setValidationState(this,
            is_valid || !isEnabled() ? QString() : QStringLiteral("invalid"));
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
