/* range_syntax_lineedit.cpp
 * Delegates for editing prefereneces.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/range_syntax_lineedit.h>

#include <epan/range.h>

RangeSyntaxLineEdit::RangeSyntaxLineEdit(QWidget *parent)
    : SyntaxLineEdit(parent),
    maxRange_(0xFFFFFFFF)
{
    connect(this, &RangeSyntaxLineEdit::textChanged, this, &RangeSyntaxLineEdit::checkRange);
}

void RangeSyntaxLineEdit::setMaxRange(unsigned int max)
{
     maxRange_ = max;
}

void RangeSyntaxLineEdit::checkRange(QString range)
{
    if (range.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    range_t *newrange;
    convert_ret_t ret = range_convert_str(NULL, &newrange, range.toUtf8().constData(), maxRange_);

    if (ret == CVT_NO_ERROR) {
        setSyntaxState(SyntaxLineEdit::Valid);
        wmem_free(NULL, newrange);
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
    }
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
