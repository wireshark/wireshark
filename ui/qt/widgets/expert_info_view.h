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
