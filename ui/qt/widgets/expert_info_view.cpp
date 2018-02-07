/* expert_info_view.cpp
 * Tree view of Expert Info data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "expert_info_view.h"
#include <ui/qt/models/expert_info_model.h>
#include <ui/qt/models/expert_info_proxy_model.h>

#include <QHeaderView>

ExpertInfoTreeView::ExpertInfoTreeView(QWidget *parent) : QTreeView(parent)
{
}

void ExpertInfoTreeView::currentChanged(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid())
    {
        if (current.parent().isValid()) {
            ((ExpertInfoProxyModel*)model())->setSeverityMode(ExpertInfoProxyModel::Packet);
        } else {
            ((ExpertInfoProxyModel*)model())->setSeverityMode(ExpertInfoProxyModel::Group);
        }

        QModelIndex model_index = ((ExpertInfoProxyModel*)model())->mapToSource(current);

        if (model_index.parent().isValid()) {
            ExpertPacketItem* currentItem = static_cast<ExpertPacketItem*>(model_index.internalPointer());
            if (currentItem != NULL)
            {
                emit goToPacket(currentItem->packetNum(), currentItem->hfId());
            }
        }
    }

    QTreeView::currentChanged(current, previous);
}

/* * Editor modelines
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
