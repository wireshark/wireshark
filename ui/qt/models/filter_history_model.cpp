/* filter_history_model.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/filter_history_model.h>

FilterHistoryModel::FilterHistoryModel(QObject *parent) :
    QAbstractListModel(parent)
{
}
