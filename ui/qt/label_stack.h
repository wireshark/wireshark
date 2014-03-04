/* label_stack.h
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

#ifndef LABEL_STACK_H
#define LABEL_STACK_H

#include <QLabel>
#include <QStack>
#include <QTime>
#include <QTimer>

class LabelStack : public QLabel
{
    Q_OBJECT
public:
    explicit LabelStack(QWidget *parent = 0);
    void setTemporaryContext(const int ctx);
    void pushText(QString &text, int ctx);

protected:
    void mousePressEvent(QMouseEvent *event);
    void mouseReleaseEvent(QMouseEvent *event);
    void mouseDoubleClickEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
    void contextMenuEvent(QContextMenuEvent *event);

private:
    typedef struct _StackItem {
        QString text;
        int ctx;
    } StackItem;

    int temporary_ctx_;
    QList<StackItem *> labels_;
    QTime  temporary_epoch_;
    QTimer temporary_timer_;

    void fillLabel();

signals:
    void toggleTemporaryFlash(bool enable);
    void mousePressedAt(const QPoint &global_pos, Qt::MouseButton button);

public slots:
    void popText(int ctx);

private slots:
    void updateTemporaryStatus();
};

#endif // LABEL_STACK_H

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
