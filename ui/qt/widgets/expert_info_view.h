/* expert_info_view.h
 * Tree view of Expert Info data.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPERT_INFO_VIEW_H
#define EXPERT_INFO_VIEW_H

#include <config.h>
#include <QTreeView>

class ExpertInfoTreeView : public QTreeView
{
    Q_OBJECT
public:
    ExpertInfoTreeView(QWidget *parent = 0);

signals:
    void goToPacket(int packet_num, int hf_id);

protected slots:
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // EXPERT_INFO_VIEW_H

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
