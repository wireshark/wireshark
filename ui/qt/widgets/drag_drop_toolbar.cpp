/* drag_drop_toolbar.cpp
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

#include <ui/qt/widgets/drag_drop_toolbar.h>
#include <ui/qt/widgets/drag_label.h>
#include <ui/qt/utils/wireshark_mime_data.h>

#include <QAction>
#include <QApplication>
#include <QToolBar>
#include <QToolButton>
#include <QDrag>
#include <QLayout>
#include <QMimeData>
#include <QMouseEvent>
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
#include <QWindow>
#endif

#define drag_drop_toolbar_action_ "drag_drop_toolbar_action_"

DragDropToolBar::DragDropToolBar(const QString &title, QWidget *parent) :
    QToolBar(title, parent)
{
    childCounter = 0;
    setAcceptDrops(true);
}

DragDropToolBar::DragDropToolBar(QWidget *parent) :
    QToolBar(parent)
{
    childCounter = 0;
    setAcceptDrops(true);
}

DragDropToolBar::~DragDropToolBar()
{
}

void DragDropToolBar::childEvent(QChildEvent * event)
{
    /* New action has been added */
    if ( event->type() == QEvent::ChildAdded )
    {
        if ( event->child()->isWidgetType() )
        {
            /* Reset if it has moved underneath lower limit */
            if ( childCounter < 0 )
                childCounter = 0;

            ((QWidget *)event->child())->installEventFilter(this);
            event->child()->setProperty(drag_drop_toolbar_action_, qVariantFromValue(childCounter));
            childCounter++;
        }
    }
    else if ( event->type() == QEvent::ChildRemoved )
    {
        childCounter--;
    }
    else if ( event->type() == QEvent::ChildPolished )
    {
        /* Polish is called every time a child is added or removed. This is implemented by adding
         * all childs again as hidden elements, and afterwards removing the existing ones. Therefore
         * we have to reset child counter here, if a widget is being polished. If this is not being
         * done, crashes will occur after an item has been removed and other items are moved afterwards */
        if ( event->child()->isWidgetType() )
            childCounter = 0;
    }
}

bool DragDropToolBar::eventFilter(QObject * obj, QEvent * event)
{
    if ( ! obj->isWidgetType() )
        return QToolBar::eventFilter(obj, event);

    QWidget * elem = qobject_cast<QWidget *>(obj);

    if ( ! elem || ( event->type() != QEvent::MouseButtonPress && event->type() != QEvent::MouseMove ) )
        return QToolBar::eventFilter(obj, event);

    QMouseEvent * ev = (QMouseEvent *)event;

    if ( event->type() == QEvent::MouseButtonPress )
    {
        if ( ev->buttons() & Qt::LeftButton )
            dragStartPosition = ev->pos();
    }
    else if ( event->type() == QEvent::MouseMove )
    {
        if ( ( ev->buttons() & Qt::LeftButton ) && (ev->pos() - dragStartPosition).manhattanLength()
                 > QApplication::startDragDistance())
        {
            ToolbarEntryMimeData * temd =
                    new ToolbarEntryMimeData(((QToolButton *)elem)->text(), elem->property(drag_drop_toolbar_action_).toInt());
            DragLabel * lbl = new DragLabel(temd->labelText(), this);
            QDrag * drag = new QDrag(this);
            drag->setMimeData(temd);

#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
            qreal dpr = window()->windowHandle()->devicePixelRatio();
            QPixmap pixmap(lbl->size() * dpr);
            pixmap.setDevicePixelRatio(dpr);
#else
            QPixmap pixmap(lbl->size());
#endif
            lbl->render(&pixmap);
            drag->setPixmap(pixmap);

            drag->exec(Qt::CopyAction | Qt::MoveAction);

            return true;
        }
    }

    return QToolBar::eventFilter(obj, event);
}

void DragDropToolBar::dragEnterEvent(QDragEnterEvent *event)
{
    if ( ! event )
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData())) {
        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData())) {
        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DragDropToolBar::dragMoveEvent(QDragMoveEvent *event)
{
    if ( ! event )
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData())) {
        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else {
        event->ignore();
    }
}

void DragDropToolBar::dropEvent(QDropEvent *event)
{
    if ( ! event )
        return;

    /* Moving items around */
    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        const ToolbarEntryMimeData * data = qobject_cast<const ToolbarEntryMimeData *>(event->mimeData());

        int oldPos = data->position();
        int newPos = -1;
        QAction * action = actionAt(event->pos());
        if ( action && actions().at(oldPos) )
        {
            widgetForAction(action)->setStyleSheet("QWidget { border: none; };");
            newPos = widgetForAction(action)->property(drag_drop_toolbar_action_).toInt();
            moveToolbarItems(oldPos, newPos);
            emit actionMoved(actions().at(oldPos), oldPos, newPos);
        }

        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }

    } else if (qobject_cast<const DisplayFilterMimeData *>(event->mimeData())) {
        const DisplayFilterMimeData * data = qobject_cast<const DisplayFilterMimeData *>(event->mimeData());

        if ( event->source() != this )
        {
            event->setDropAction(Qt::CopyAction);
            event->accept();

            emit newFilterDropped(data->description(), data->filter());

        } else {
            event->acceptProposedAction();
        }

    } else {
        event->ignore();
    }
}

void DragDropToolBar::moveToolbarItems(int fromPos, int newPos)
{
    if ( fromPos == newPos )
        return;

    setUpdatesEnabled(false);

    QList<QAction *> storedActions = actions();

    clear();
    childCounter = 0;

    storedActions.move(fromPos, newPos);
    foreach ( QAction * action, storedActions )
        addAction(action);

    setUpdatesEnabled(true);
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
