/* packet_list_header.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QDropEvent>
#include <QMimeData>
#include <QToolTip>

#include <wireshark_application.h>
#include <ui/qt/main_window.h>

#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/widgets/packet_list_header.h>

PacketListHeader::PacketListHeader(Qt::Orientation orientation, QWidget *parent) :
    QHeaderView(orientation, parent)
{
    setAcceptDrops(true);
    setSectionsMovable(true);
    setStretchLastSection(true);
    setDefaultAlignment(Qt::AlignLeft|Qt::AlignVCenter);
}

void PacketListHeader::dragEnterEvent(QDragEnterEvent *event)
{
    if ( ! event )
        return;

    if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData()))
    {
        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    }
    else
        QHeaderView::dragEnterEvent(event);
}

void PacketListHeader::dragMoveEvent(QDragMoveEvent *event)
{
    if ( ! event )
        return;

    if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData()))
    {
        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    }
    else
        QHeaderView::dragMoveEvent(event);
}

void PacketListHeader::dropEvent(QDropEvent *event)
{
    if ( ! event )
        return;

    /* Moving items around */
    if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData())) {
        const DisplayFilterMimeData * data = qobject_cast<const DisplayFilterMimeData *>(event->mimeData());

        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();

            MainWindow * mw = qobject_cast<MainWindow *>(wsApp->mainWindow());
            if ( mw )
            {
                int idx = logicalIndexAt(event->pos());
                mw->insertColumn(data->description(), data->field(), idx);
            }

        } else {
            event->acceptProposedAction();
        }
    }
    else
        QHeaderView::dropEvent(event);
}

void PacketListHeader::mousePressEvent(QMouseEvent *e)
{
    if ( e->button() == Qt::LeftButton && sectionIdx < 0 )
    {
        /* No move happening yet */
        int sectIdx = logicalIndexAt(e->localPos().x() - 4, e->localPos().y());

        QString headerName = model()->headerData(sectIdx, orientation()).toString();
        lastSize = sectionSize(sectIdx);
        QToolTip::showText(e->globalPos(), QString("Width: %1").arg(sectionSize(sectIdx)));
    }
    QHeaderView::mousePressEvent(e);
}

void PacketListHeader::mouseMoveEvent(QMouseEvent *e)
{
    if ( e->button() == Qt::NoButton || ! ( e->buttons() & Qt::LeftButton) )
    {
        /* no move is happening */
        sectionIdx = -1;
        lastSize = -1;
    }
    else if ( e->buttons() & Qt::LeftButton )
    {
        /* section being moved */
        int triggeredSection = logicalIndexAt(e->localPos().x() - 4, e->localPos().y());

        if ( sectionIdx < 0 )
            sectionIdx = triggeredSection;
        else if ( sectionIdx == triggeredSection )
        {
            /* Only run for the current moving section after a change */
            QString headerName = model()->headerData(sectionIdx, orientation()).toString();
            lastSize = sectionSize(sectionIdx);
            QToolTip::showText(e->globalPos(), QString("Width: %1").arg(lastSize));
        }
    }
    QHeaderView::mouseMoveEvent(e);
}

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
