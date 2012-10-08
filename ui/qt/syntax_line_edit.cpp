#include "syntax_line_edit.h"

#include "tango_colors.h"
#include <QDebug>

SyntaxLineEdit::SyntaxLineEdit(QWidget *parent) :
    QLineEdit(parent)
{
    state_style_sheet_ = QString(
            "SyntaxLineEdit[syntaxState=\"%1\"] {"
            "  color: #%4;"
            "  background-color: #%5;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%2\"] {"
            "  color: #%4;"
            "  background-color: #%6;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%3\"] {"
            "  color: #%4;"
            "  background-color: #%7;"
            "}"
            )
            .arg(Invalid)
            .arg(Deprecated)
            .arg(Valid)
            .arg(tango_aluminium_6, 6, 16, QChar('0'))   // Foreground
            .arg(tango_scarlet_red_1, 6, 16, QChar('0')) // Invalid
            .arg(tango_butter_1, 6, 16, QChar('0'))      // Deprecated
            .arg(tango_chameleon_1, 6, 16, QChar('0'))   // Valid
            ;
    setStyleSheet(tr(""));
    setSyntaxState();
}

void SyntaxLineEdit::setSyntaxState(SyntaxState state) {
    syntax_state_ = state;
    setStyleSheet(style_sheet_);
}

QString SyntaxLineEdit::styleSheet() const {
    return style_sheet_;
}

void SyntaxLineEdit::setStyleSheet(const QString &style_sheet) {
    style_sheet_ = style_sheet;
    QLineEdit::setStyleSheet(style_sheet_ + state_style_sheet_);
}
