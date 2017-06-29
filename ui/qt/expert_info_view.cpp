/* expert_info_view.cpp
 * Tree view of Expert Info data.
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

#include "expert_info_view.h"
#include "expert_info_model.h"
#include "expert_info_proxy_model.h"

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
