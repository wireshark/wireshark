/* in_packet_find_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_find_edit.h"

#include <QTimer>

InPacketFindEdit::InPacketFindEdit(QWidget *parent) :
    FilterEdit(parent)
{
    disableFilterValidation();
}

void InPacketFindEdit::disableFilterValidation()
{
    // FilterEdit connects textChanged -> onTextChanged -> debounce -> validateNow()
    if (QTimer *debounce = findChild<QTimer *>()) {
        disconnect(debounce, &QTimer::timeout, this, nullptr);
    }
}

void InPacketFindEdit::updateSearchSyntax(bool empty, bool regex_invalid)
{
    if (empty || regex_invalid) {
        setState(SyntaxState::Invalid);
    } else {
        setState(SyntaxState::Valid);
    }
}

void InPacketFindEdit::clearSearchSyntax()
{
    setState(SyntaxState::Empty);
}
