/* stratoshark_search_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_search_frame.h"
#include "search_frame.h"

StratosharkSearchFrame::StratosharkSearchFrame(QWidget *parent) :
    SearchFrame(parent)
{
    searchInComboBox()->setItemText(0, tr("Event List"));
    searchInComboBox()->setItemText(1, tr("Event Details"));
    searchInComboBox()->setItemText(2, tr("Event Bytes"));
    searchInComboBox()->setToolTip(tr("<html><head/><body>"
                                            "<p>Search the Info column of the event list (summary pane), "
                                            "decoded event display labels (tree view pane) or the "
                                            "ASCII-converted event data (hex view pane).</p>"
                                            "</body></html>"));

    updateWidgets();
}

StratosharkSearchFrame::~StratosharkSearchFrame()
{
}
