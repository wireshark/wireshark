/* apply_lineedit.cpp
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

#include <ui/qt/apply_line_edit.h>

#include <epan/prefs.h>

#include <ui/qt/color_utils.h>

#include <QRegExp>
#include <QRegExpValidator>
#include <QStyle>

ApplyLineEdit::ApplyLineEdit(QString linePlaceholderText, QWidget * parent)
: QLineEdit(parent),
  applyButton(0)
{
    emptyAllowed_ = false;
    regex_ = QString();

    applyButton = new StockIconToolButton(parent, "x-filter-apply");
    applyButton->setCursor(Qt::ArrowCursor);
    applyButton->setEnabled(false);
    applyButton->setToolTip(tr("Apply changes"));
    applyButton->setIconSize(QSize(24, 14));
    applyButton->setMaximumWidth(30);
    applyButton->setStyleSheet(
            "QToolButton {"
            "  border: none;"
            "  background: transparent;" // Disables platform style on Windows.
            "  padding: 0 0 0 0;"
            "}"
            );

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacSmallSize, true);
    applyButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    setPlaceholderText(linePlaceholderText);

    connect(this, SIGNAL(textEdited(const QString&)), this, SLOT(onTextEdited(const QString&)));
    connect(this, SIGNAL(textChanged(const QString&)), this, SLOT(onTextChanged(const QString&)));

    connect(this, SIGNAL(returnPressed()), this, SLOT(onSubmitContent()));
    connect(applyButton, SIGNAL(clicked()), this, SLOT(onSubmitContent()));

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
    if ( text.length() == 0 )
    {
        if ( ! ignoreEmptyCheck && ! emptyAllowed_ )
            return false;
        else if ( ignoreEmptyCheck )
            return true;
    }

    if ( regex_.length() > 0 )
    {
        QRegExp rx ( regex_ );
        QRegExpValidator v(rx, 0);

        int pos = 0;
        if ( ! rx.isValid() || v.validate(text, pos) != QValidator::Acceptable )
            return false;
    }

    return true;
}

void ApplyLineEdit::onTextEdited(const QString & text)
{
    QString newText = QString(text);
    applyButton->setEnabled(isValidText(newText));
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
            .arg(applyButton->sizeHint().width() + frameWidth)
            .arg(isValidText(newText, true) ? QString("") : ColorUtils::fromColorT(prefs.gui_text_invalid).name());

    setStyleSheet(style_sheet);
}

void ApplyLineEdit::resizeEvent(QResizeEvent *)
{
    int frameWidth = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    QSize apsz = applyButton->sizeHint();

    applyButton->move((contentsRect().right() + pos().x()) - ( frameWidth + apsz.width() ) - 2,
                        contentsRect().top() + pos().y());

    applyButton->setMinimumHeight(height());
    applyButton->setMaximumHeight(height());
}

void ApplyLineEdit::onSubmitContent()
{
    QString data = text();
    if ( ! isValidText(data) )
        return;

    /* Freeze apply button to signal the text has been sent. Will be unfreezed, if the text in the textbox changes again */
    applyButton->setEnabled(false);

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
