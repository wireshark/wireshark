/* syntax_line_edit.cpp
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

#include <glib.h>

#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>

#include "syntax_line_edit.h"

#include "color_utils.h"

SyntaxLineEdit::SyntaxLineEdit(QWidget *parent) :
    QLineEdit(parent)
{
    setSyntaxState();
}

void SyntaxLineEdit::setSyntaxState(SyntaxState state) {
    syntax_state_ = state;
    state_style_sheet_ = QString(
            "SyntaxLineEdit[syntaxState=\"%1\"] {"
            "  color: %4;"
            "  background-color: %5;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%2\"] {"
            "  color: %4;"
            "  background-color: %6;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%3\"] {"
            "  color: %4;"
            "  background-color: %7;"
            "}"
            )
            .arg(Valid)
            .arg(Invalid)
            .arg(Deprecated)
            .arg("palette(text)")   // Foreground
            .arg(ColorUtils::fromColorT(&prefs.gui_text_valid).name()) // Invalid
            .arg(ColorUtils::fromColorT(&prefs.gui_text_invalid).name())      // Deprecated
            .arg(ColorUtils::fromColorT(&prefs.gui_text_deprecated).name())   // Valid
            ;
    setStyleSheet(style_sheet_);
}

QString SyntaxLineEdit::styleSheet() const {
    return style_sheet_;
}

QString SyntaxLineEdit::deprecatedToken()
{
    return deprecated_token_;
}

void SyntaxLineEdit::setStyleSheet(const QString &style_sheet) {
    style_sheet_ = style_sheet;
    QLineEdit::setStyleSheet(style_sheet_ + state_style_sheet_);
}

void SyntaxLineEdit::checkDisplayFilter(QString filter)
{
    if (filter.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    deprecated_token_.clear();
    dfilter_t *dfp = NULL;
    bool valid = dfilter_compile(filter.toUtf8().constData(), &dfp);

    if (valid) {
        setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        GPtrArray *depr = NULL;
        if (dfp) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (depr) {
            setSyntaxState(SyntaxLineEdit::Deprecated);
            deprecated_token_ = (const char *) g_ptr_array_index(depr, 0);
        } else {
            setSyntaxState(SyntaxLineEdit::Invalid);
        }
    }
    dfilter_free(dfp);
}

void SyntaxLineEdit::checkFieldName(QString field)
{
    if (field.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    char invalid_char = proto_check_field_name(field.toUtf8().constData());
    if (invalid_char) {
        setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        checkDisplayFilter(field);
    }
}
