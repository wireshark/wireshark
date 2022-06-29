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
#include <QAction>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>

#include <packet_list.h>

#include <main_application.h>
#include <epan/column.h>
#include <ui/recent.h>
#include <ui/preference_utils.h>
#include <ui/packet_list_utils.h>
#include <ui/qt/main_window.h>

#include <models/packet_list_model.h>
#include <models/pref_models.h>
#include <ui/qt/utils/wireshark_mime_data.h>
#include <ui/qt/widgets/packet_list_header.h>

PacketListHeader::PacketListHeader(Qt::Orientation orientation, QWidget *parent) :
    QHeaderView(orientation, parent),
    sectionIdx(-1)
{
    setAcceptDrops(true);
    setSectionsMovable(true);
    setStretchLastSection(true);
    setDefaultAlignment(Qt::AlignLeft|Qt::AlignVCenter);
}

void PacketListHeader::dragEnterEvent(QDragEnterEvent *event)
{
    if (! event || ! event->mimeData())
        return;

    if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType) && event->source() != this->parent())
    {
        if (event->source() != this)
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
    if (! event || ! event->mimeData())
        return;

    if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType))
    {
        if (event->source() != this)
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
    if (! event || ! event->mimeData())
        return;

    /* Moving items around */
    if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType))
    {
        QByteArray jsonData = event->mimeData()->data(WiresharkMimeData::DisplayFilterMimeType);
        QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
        if (! jsonDoc.isObject())
            return;

        QJsonObject data = jsonDoc.object();

        if ( event->source() != this && data.contains("description") && data.contains("name") )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();

            MainWindow * mw = qobject_cast<MainWindow *>(mainApp->mainWindow());
            if (mw)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
                int idx = logicalIndexAt(event->position().toPoint());
#else
                int idx = logicalIndexAt(event->pos());
#endif
                mw->insertColumn(data["description"].toString(), data["name"].toString(), idx);
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
    if (e->button() == Qt::LeftButton && sectionIdx < 0)
    {
        /* No move happening yet */
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        int sectIdx = logicalIndexAt(e->position().toPoint().x() - 4, e->position().toPoint().y());
#else
        int sectIdx = logicalIndexAt(e->localPos().x() - 4, e->localPos().y());
#endif

        QString headerName = model()->headerData(sectIdx, orientation()).toString();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        QToolTip::showText(e->globalPosition().toPoint(), QString("Width: %1").arg(sectionSize(sectIdx)));
#else
        QToolTip::showText(e->globalPos(), QString("Width: %1").arg(sectionSize(sectIdx)));
#endif
    }
    QHeaderView::mousePressEvent(e);
}

void PacketListHeader::mouseMoveEvent(QMouseEvent *e)
{
    if (e->button() == Qt::NoButton || ! (e->buttons() & Qt::LeftButton))
    {
        /* no move is happening */
        sectionIdx = -1;
    }
    else if (e->buttons() & Qt::LeftButton)
    {
        /* section being moved */
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        int triggeredSection = logicalIndexAt(e->position().toPoint().x() - 4, e->position().toPoint().y());
#else
        int triggeredSection = logicalIndexAt(e->localPos().x() - 4, e->localPos().y());
#endif

        if (sectionIdx < 0)
            sectionIdx = triggeredSection;
        else if (sectionIdx == triggeredSection)
        {
            /* Only run for the current moving section after a change */
            QString headerName = model()->headerData(sectionIdx, orientation()).toString();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
            QToolTip::showText(e->globalPosition().toPoint(), QString("Width: %1").arg(sectionSize(sectionIdx)));
#else
            QToolTip::showText(e->globalPos(), QString("Width: %1").arg(sectionSize(sectionIdx)));
#endif
        }
    }
    QHeaderView::mouseMoveEvent(e);
}

void PacketListHeader::contextMenuEvent(QContextMenuEvent *event)
{
    int sectionIdx = logicalIndexAt(event->pos());
    if (sectionIdx < 0 || sectionIdx >= prefs.num_cols)
        return;

    char xalign = recent_get_column_xalign(sectionIdx);
    QAction * action = nullptr;

    QMenu * contextMenu = new QMenu(this);
    contextMenu->setProperty("column", QVariant::fromValue(sectionIdx));

    QActionGroup * alignmentActions = new QActionGroup(contextMenu);
    alignmentActions->setExclusive(false);
    alignmentActions->setProperty("column", QVariant::fromValue(sectionIdx));
    action = alignmentActions->addAction(tr("Align Left"));
    action->setCheckable(true);
    action->setChecked(xalign == COLUMN_XALIGN_LEFT ? true : false);
    action->setData(QVariant::fromValue(COLUMN_XALIGN_LEFT));
    action = alignmentActions->addAction(tr("Align Center"));
    action->setCheckable(true);
    action->setChecked(xalign == COLUMN_XALIGN_CENTER ? true : false);
    action->setData(QVariant::fromValue(COLUMN_XALIGN_CENTER));
    action = alignmentActions->addAction(tr("Align Right"));
    action->setCheckable(true);
    action->setChecked(xalign == COLUMN_XALIGN_RIGHT ? true : false);
    action->setData(QVariant::fromValue(COLUMN_XALIGN_RIGHT));
    connect(alignmentActions, &QActionGroup::triggered, this, &PacketListHeader::setAlignment);

    contextMenu->addActions(alignmentActions->actions());
    contextMenu->addSeparator();

    action = contextMenu->addAction(tr("Column Preferences…"));
    connect(action, &QAction::triggered, this, &PacketListHeader::showColumnPrefs);
    action = contextMenu->addAction(tr("Edit Column"));
    connect(action, &QAction::triggered, this, &PacketListHeader::doEditColumn);
    action = contextMenu->addAction(tr("Resize to Contents"));
    connect(action, &QAction::triggered, this, &PacketListHeader::resizeToContent);
    action = contextMenu->addAction(tr("Resize Column to Width…"));
    connect(action, &QAction::triggered, this, &PacketListHeader::resizeToWidth);

    action = contextMenu->addAction(tr("Resolve Names"));
    bool canResolve = model()->headerData(sectionIdx, Qt::Horizontal, PacketListModel::HEADER_CAN_RESOLVE).toBool();
    action->setEnabled(canResolve);
    action->setCheckable(true);
    action->setChecked(canResolve && get_column_resolved(sectionIdx));
    connect(action, &QAction::triggered, this, &PacketListHeader::doResolveNames);

    contextMenu->addSeparator();

    for (int cnt = 0; cnt < prefs.num_cols; cnt++) {
        QString title(get_column_title(cnt));
        QString detail;
        if (get_column_format(cnt) == COL_CUSTOM) {
            detail = get_column_custom_fields(cnt);
        } else {
            detail = col_format_desc(get_column_format(cnt));
        }

        if (prefs.gui_qt_packet_header_column_definition)
            title.append(QString("\t%1").arg(detail));

        QAction *action = new QAction(title, this);
        action->setToolTip(detail);
        action->setCheckable(true);
        action->setChecked(get_column_visible(cnt));
        action->setData(QVariant::fromValue(cnt));
        connect(action, &QAction::triggered, this, &PacketListHeader::columnVisibilityTriggered);
        contextMenu->addAction(action);
    }
    contextMenu->setToolTipsVisible(true);

    contextMenu->addSeparator();

    action = contextMenu->addAction(tr("Remove this Column"));
    action->setEnabled(sectionIdx >= 0 && count() > 2);
    connect(action, &QAction::triggered, this, &PacketListHeader::removeColumn);

    contextMenu->popup(viewport()->mapToGlobal(event->pos()));
}

void PacketListHeader::columnVisibilityTriggered()
{
    QAction *ha = qobject_cast<QAction*>(sender());
    if (!ha) return;

    int col = ha->data().toInt();
    set_column_visible(col, ha->isChecked());
    setSectionHidden(col, ha->isChecked() ? false : true);
    if (ha->isChecked())
        emit resetColumnWidth(col);

    prefs_main_write();
}

void PacketListHeader::setAlignment(QAction *action)
{
    if (!action)
        return;

    QActionGroup * group = action->actionGroup();
    if (! group)
        return;

    int section = group->property("column").toInt();
    if (section >= 0)
    {
        QChar data = action->data().toChar();
        recent_set_column_xalign(section, action->isChecked() ? data.toLatin1() : COLUMN_XALIGN_DEFAULT);
        emit updatePackets(false);
    }
}

void PacketListHeader::showColumnPrefs()
{
    emit showColumnPreferences(PrefsModel::typeToString(PrefsModel::Columns));
}

void PacketListHeader::doEditColumn()
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (!action)
        return;

    QMenu * menu = qobject_cast<QMenu *>(action->parent());
    if (! menu)
        return;

    int section = menu->property("column").toInt();
    emit editColumn(section);
}

void PacketListHeader::doResolveNames()
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (!action)
        return;

    QMenu * menu = qobject_cast<QMenu *>(action->parent());
    if (!menu)
        return;

    int section = menu->property("column").toInt();

    set_column_resolved(section, action->isChecked());
    prefs_main_write();
    emit updatePackets(true);
}

void PacketListHeader::resizeToContent()
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (!action)
        return;

    QMenu * menu = qobject_cast<QMenu *>(action->parent());
    if (!menu)
        return;

    int section = menu->property("column").toInt();
    PacketList * packetList = qobject_cast<PacketList *>(parent());
    if (packetList)
        packetList->resizeColumnToContents(section);
}

void PacketListHeader::removeColumn()
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (!action)
        return;

    QMenu * menu = qobject_cast<QMenu *>(action->parent());
    if (!menu)
        return;

    int section = menu->property("column").toInt();

    if (count() > 2) {
        column_prefs_remove_nth(section);
        emit columnsChanged();
        prefs_main_write();
    }
}

void PacketListHeader::resizeToWidth()
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (!action)
        return;

    QMenu * menu = qobject_cast<QMenu *>(action->parent());
    if (!menu)
        return;

    bool ok = false;
    int width = -1;
    int section = menu->property("column").toInt();
    QString headerName = model()->headerData(section, orientation()).toString();
    width = QInputDialog::getInt(this, tr("Column %1").arg(headerName), tr("Width:"),
                                 sectionSize(section), 0, 1000, 1, &ok);
    if (ok)
        resizeSection(section, width);
}
