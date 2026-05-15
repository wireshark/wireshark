/** @file
 *
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

/**
 * @brief A custom tree view for displaying expert information.
 */
class ExpertInfoTreeView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ExpertInfoTreeView.
     * @param parent The parent widget, defaults to 0.
     */
    ExpertInfoTreeView(QWidget *parent = 0);

signals:
    /**
     * @brief Signal emitted to navigate to a specific packet.
     * @param packet_num The target packet number.
     * @param hf_id The associated header field ID.
     */
    void goToPacket(int packet_num, int hf_id);

protected slots:
    /**
     * @brief Handles the event when the current item selection changes.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void currentChanged(const QModelIndex &current, const QModelIndex &previous);
};
#endif // EXPERT_INFO_VIEW_H
