/* packet_list_header.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_WIDGETS_PACKET_LIST_HEADER_H_
#define UI_QT_WIDGETS_PACKET_LIST_HEADER_H_

#include <cfile.h>

#include <QHeaderView>
#include <QDrag>
#include <QMenu>

class QEvent;

class PacketListHeader : public QHeaderView
{
    Q_OBJECT

public:
    PacketListHeader(Qt::Orientation orientation, capture_file * cap_file, QWidget *parent = nullptr);

    void setCaptureFile(capture_file * cap_file);

protected:
    virtual void dropEvent(QDropEvent *event) override;
    virtual void dragEnterEvent(QDragEnterEvent *event) override;
    virtual void dragMoveEvent(QDragMoveEvent *event) override;

    virtual void mouseMoveEvent(QMouseEvent *e) override;
    virtual void mousePressEvent(QMouseEvent *e) override;

    virtual void contextMenuEvent(QContextMenuEvent *event) override;

protected slots:
    void columnVisibilityTriggered();

    void setAlignment(QAction *);

    void showColumnPrefs();
    void doEditColumn();
    void doResolveNames();
    void resizeToContent();
    void removeColumn();
    void resizeToWidth();

signals:
    void resetColumnWidth(int col);
    void updatePackets(bool redraw);
    void showColumnPreferences(QString pane_name);
    void editColumn(int column);

    void columnsChanged();

private:

    capture_file * cap_file_;
    int sectionIdx;
    int lastSize;

    void setSectionVisibility();
};

#endif

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
