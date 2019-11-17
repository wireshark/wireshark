/* drag_drop_toolbar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wsutil/utf8_entities.h>

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
#include <QWindow>
#include <QJsonObject>
#include <QJsonDocument>

#define drag_drop_toolbar_action_ "drag_drop_toolbar_action_"

DragDropToolBar::DragDropToolBar(const QString &title, QWidget *parent) :
    QToolBar(title, parent)
{
    setupToolbar();
}

DragDropToolBar::DragDropToolBar(QWidget *parent) :
    QToolBar(parent)
{
    setupToolbar();
}

void DragDropToolBar::setupToolbar()
{
    childCounter = 0;
    setAcceptDrops(true);

    // Each QToolBar has a QToolBarExtension button. Its icon looks
    // terrible. We might want to create our own icon, but the double
    // angle quote is a similar, nice-looking shape.
    QToolButton *ext_button = findChild<QToolButton*>();
    if (ext_button) {
        ext_button->setIcon(QIcon());
        ext_button->setText(UTF8_RIGHT_POINTING_DOUBLE_ANGLE_QUOTATION_MARK);
    }
}

DragDropToolBar::~DragDropToolBar()
{
}

void DragDropToolBar::childEvent(QChildEvent * event)
{
    /* New action has been added */
    if (event->type() == QEvent::ChildAdded)
    {
        if (event->child()->isWidgetType())
        {
            /* Reset if it has moved underneath lower limit */
            if (childCounter < 0)
                childCounter = 0;

            ((QWidget *)event->child())->installEventFilter(this);
            event->child()->setProperty(drag_drop_toolbar_action_, QVariant::fromValue(childCounter));
            childCounter++;
        }
    }
    else if (event->type() == QEvent::ChildRemoved)
    {
        childCounter--;
    }
    else if (event->type() == QEvent::ChildPolished)
    {
        /* Polish is called every time a child is added or removed. This is implemented by adding
         * all childs again as hidden elements, and afterwards removing the existing ones. Therefore
         * we have to reset child counter here, if a widget is being polished. If this is not being
         * done, crashes will occur after an item has been removed and other items are moved afterwards */
        if (event->child()->isWidgetType())
            childCounter = 0;
    }
}

void DragDropToolBar::clear()
{
    QToolBar::clear();
    childCounter = 0;
}

WiresharkMimeData * DragDropToolBar::createMimeData(QString name, int position)
{
    return new ToolbarEntryMimeData(name, position);
}

bool DragDropToolBar::eventFilter(QObject * obj, QEvent * event)
{
    if (! obj->isWidgetType())
        return QToolBar::eventFilter(obj, event);

    QWidget * elem = qobject_cast<QWidget *>(obj);

    if (! elem || (event->type() != QEvent::MouseButtonPress && event->type() != QEvent::MouseMove) )
        return QToolBar::eventFilter(obj, event);

    QMouseEvent * ev = (QMouseEvent *)event;

    if (event->type() == QEvent::MouseButtonPress)
    {
        if (ev->buttons() & Qt::LeftButton)
            dragStartPosition = ev->pos();
    }
    else if (event->type() == QEvent::MouseMove)
    {
        if ((ev->buttons() & Qt::LeftButton) && (ev->pos() - dragStartPosition).manhattanLength()
                 > QApplication::startDragDistance())
        {
            if (! qobject_cast<QToolButton *>(elem) || ! elem->property(drag_drop_toolbar_action_).isValid())
                return QToolBar::eventFilter(obj, event);

            WiresharkMimeData * temd = createMimeData(((QToolButton *)elem)->text(), elem->property(drag_drop_toolbar_action_).toInt());
            DragLabel * lbl = new DragLabel(temd->labelText(), this);
            QDrag * drag = new QDrag(this);
            drag->setMimeData(temd);

            qreal dpr = window()->windowHandle()->devicePixelRatio();
            QPixmap pixmap(lbl->size() * dpr);
            pixmap.setDevicePixelRatio(dpr);

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
    if (! event || ! event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this)
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
    if (! event || ! event->mimeData())
        return;

    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        QAction * actionAtPos = actionAt(event->pos());
        if (actionAtPos)
        {
            QWidget * widget = widgetForAction(actionAtPos);
            if (widget)
            {
                bool success = false;
                widget->property(drag_drop_toolbar_action_).toInt(&success);
                if (! success)
                {
                    event->ignore();
                    return;
                }
            }
        }

        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }
    } else if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        if (event->source() != this)
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
    if (! event || ! event->mimeData())
        return;

    /* Moving items around */
    if (qobject_cast<const ToolbarEntryMimeData *>(event->mimeData()))
    {
        const ToolbarEntryMimeData * data = qobject_cast<const ToolbarEntryMimeData *>(event->mimeData());

        int oldPos = data->position();
        int newPos = -1;
        QAction * action = actionAt(event->pos());
        if (action && actions().at(oldPos))
        {
            widgetForAction(action)->setStyleSheet("QWidget { border: none; };");
            newPos = widgetForAction(action)->property(drag_drop_toolbar_action_).toInt();
            moveToolbarItems(oldPos, newPos);
            QAction * moveAction = actions().at(oldPos);

            emit actionMoved(moveAction, oldPos, newPos);
        }

        if (event->source() == this) {
            event->setDropAction(Qt::MoveAction);
            event->accept();
        } else {
            event->acceptProposedAction();
        }

    } else if (event->mimeData()->hasFormat(WiresharkMimeData::DisplayFilterMimeType)) {
        QByteArray jsonData = event->mimeData()->data(WiresharkMimeData::DisplayFilterMimeType);
        QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData);
        if (jsonDoc.isObject())
        {
            QJsonObject data = jsonDoc.object();

            if (event->source() != this && data.contains("description") && data.contains("filter"))
            {
                event->setDropAction(Qt::CopyAction);
                event->accept();

                emit newFilterDropped(data["description"].toString(), data["filter"].toString());

            } else {
                event->acceptProposedAction();
            }
        }
    } else {
        event->ignore();
    }
}

void DragDropToolBar::moveToolbarItems(int fromPos, int newPos)
{
    if (fromPos == newPos)
        return;

    setUpdatesEnabled(false);

    QList<QAction *> storedActions = actions();

    clear();
    childCounter = 0;

    storedActions.move(fromPos, newPos);
    foreach (QAction * action, storedActions)
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
