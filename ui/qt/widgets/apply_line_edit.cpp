/* apply_lineedit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/apply_line_edit.h>

#include <epan/prefs.h>

#include <ui/qt/utils/color_utils.h>

#include <QRegExp>
#include <QRegExpValidator>
#include <QStyle>

ApplyLineEdit::ApplyLineEdit(QString linePlaceholderText, QWidget * parent)
: QLineEdit(parent),
  apply_button_(0)
{
    emptyAllowed_ = false;
    regex_ = QString();

    apply_button_ = new StockIconToolButton(parent, "x-filter-apply");
    apply_button_->setCursor(Qt::ArrowCursor);
    apply_button_->setEnabled(false);
    apply_button_->setToolTip(tr("Apply changes"));
    apply_button_->setIconSize(QSize(24, 14));
    apply_button_->setMaximumWidth(30);
    apply_button_->setStyleSheet(
            "QToolButton {"
            "  border: none;"
            "  background: transparent;" // Disables platform style on Windows.
            "  padding: 0 0 0 0;"
            "}"
            );

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacSmallSize, true);
    apply_button_->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    setPlaceholderText(linePlaceholderText);

    connect(this, &ApplyLineEdit::textEdited, this, &ApplyLineEdit::onTextEdited);
    connect(this, &ApplyLineEdit::textChanged, this, &ApplyLineEdit::onTextChanged);

    connect(this, &ApplyLineEdit::returnPressed, this, &ApplyLineEdit::onSubmitContent);
    connect(apply_button_, &StockIconToolButton::clicked, this, &ApplyLineEdit::onSubmitContent);

    handleValidation(QString(linePlaceholderText));

    setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
}

ApplyLineEdit::~ApplyLineEdit() {}

void ApplyLineEdit::setRegEx(QString regex)
{
    regex_ = regex;
}

QString ApplyLineEdit::regex()
{
    return regex_;
}

void ApplyLineEdit::setEmptyAllowed(bool emptyAllowed)
{
    emptyAllowed_ = emptyAllowed;
}

bool ApplyLineEdit::emptyAllowed()
{
    return emptyAllowed_;
}

bool ApplyLineEdit::isValidText(QString & text, bool ignoreEmptyCheck)
{
    if (text.length() == 0)
    {
        if (! ignoreEmptyCheck && ! emptyAllowed_)
            return false;
        else if (ignoreEmptyCheck)
            return true;
    }

    if (regex_.length() > 0)
    {
        QRegExp rx (regex_);
        QRegExpValidator v(rx, 0);

        int pos = 0;
        if (! rx.isValid() || v.validate(text, pos) != QValidator::Acceptable)
            return false;
    }

    return true;
}

void ApplyLineEdit::onTextEdited(const QString & text)
{
    QString newText = QString(text);
    apply_button_->setEnabled(isValidText(newText));
    handleValidation(newText);
}

void ApplyLineEdit::onTextChanged(const QString & text)
{
    handleValidation(QString(text));
}

void ApplyLineEdit::handleValidation(QString newText)
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);

    QString style_sheet = QString(
            "ApplyLineEdit {"
            "  padding-left: %1px;"
            "  padding-right: %2px;"
            "  background-color: %3;"
            "}"
            )
            .arg(frameWidth + 1)
            .arg(apply_button_->sizeHint().width() + frameWidth)
            .arg(isValidText(newText, true) ? QString("") : ColorUtils::fromColorT(prefs.gui_text_invalid).name());

    setStyleSheet(style_sheet);
}

void ApplyLineEdit::resizeEvent(QResizeEvent *)
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize apsz = apply_button_->sizeHint();

    apply_button_->move((contentsRect().right() + pos().x()) - (frameWidth + apsz.width()) - 2,
                        contentsRect().top() + pos().y());

    apply_button_->setMinimumHeight(height());
    apply_button_->setMaximumHeight(height());
}

void ApplyLineEdit::onSubmitContent()
{
    QString data = text();
    if (! isValidText(data))
        return;

    /* Freeze apply button to signal the text has been sent. Will be unfreezed, if the text in the textbox changes again */
    apply_button_->setEnabled(false);

    emit textApplied();
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
