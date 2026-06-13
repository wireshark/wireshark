/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IN_PACKET_FIND_EDIT_H
#define IN_PACKET_FIND_EDIT_H

#include "filter_edit.h"

/**
 * @brief FilterEdit for the single-packet find bar (string/regex syntax tint only).
 *
 * The main-window Find Packet field remains DisplayFilterEdit until that site
 * is migrated separately.
 */
class InPacketFindEdit : public FilterEdit
{
    Q_OBJECT

public:
    explicit InPacketFindEdit(QWidget *parent = nullptr);

    /** @brief Drive invalid/valid tint from in-packet search results. */
    void updateSearchSyntax(bool empty, bool regex_invalid);

    /** @brief Neutral field tint when the bar is closed. */
    void clearSearchSyntax();

private:
    void disableFilterValidation();
};

#endif // IN_PACKET_FIND_EDIT_H
