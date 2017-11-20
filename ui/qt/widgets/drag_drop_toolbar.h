/* drag_drop_toolbar.h
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

#ifndef DRAG_DROP_TOOLBAR_H
#define DRAG_DROP_TOOLBAR_H

#include <QToolBar>
#include <QPoint>
#include <ui/qt/utils/qt_ui_utils.h>

class DragDropToolBar : public QToolBar
{
    Q_OBJECT
public:
    explicit DragDropToolBar(const QString &title, QWidget *parent = Q_NULLPTR);
    explicit DragDropToolBar(QWidget *parent = Q_NULLPTR);
    ~DragDropToolBar();

    virtual void clear();

Q_SIGNALS:
    void actionMoved(QAction * action, int oldPos, int newPos);

    void newFilterDropped(QString description, QString filter);

protected:

    virtual void childEvent(QChildEvent * event);

    virtual bool eventFilter(QObject * obj, QEvent * ev);
    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dragMoveEvent(QDragMoveEvent *event);
    virtual void dropEvent(QDropEvent *event);

private:

    QPoint dragStartPosition;
    int childCounter;

    void moveToolbarItems(int fromPos, int toPos);

};

#endif // DRAG_DROP_TOOLBAR_H

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
