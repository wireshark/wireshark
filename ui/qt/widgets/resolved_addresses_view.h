/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_VIEW_H
#define RESOLVED_ADDRESSES_VIEW_H

#include <ui/qt/models/resolved_addresses_models.h>

#include <QTableView>
#include <QMenu>

class ResolvedAddressesView : public QTableView
{
    Q_OBJECT

public:
    typedef enum {
        EXPORT_TEXT,
        EXPORT_CSV,
        EXPORT_JSON
    } eResolvedAddressesExport;

    ResolvedAddressesView(QWidget *parent = nullptr);

    QMenu* createCopyMenu(bool selected = false, QWidget *parent = nullptr);

public slots:
    void saveAs();

protected:
    void contextMenuEvent(QContextMenuEvent *e) override;

private:
    QAction *clip_action_;

    AStringListListModel* dataModel() const;
    void copyToClipboard(eResolvedAddressesExport format, bool selected);

private slots:
    void clipboardAction();
    void toTextStream(QTextStream &stream, eResolvedAddressesExport format, bool selected = false) const;
};

#endif // RESOLVED_ADDRESSES_VIEW_H
