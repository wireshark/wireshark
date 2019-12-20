/* label_stack.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LABEL_STACK_H
#define LABEL_STACK_H

#include <QLabel>
#include <QStack>
#include <QElapsedTimer>
#include <QTimer>

class LabelStack : public QLabel
{
    Q_OBJECT
public:
    explicit LabelStack(QWidget *parent = 0);
    void setTemporaryContext(const int ctx);
    void pushText(const QString &text, int ctx);
    void setShrinkable(bool shrinkable = true);

protected:
    void mousePressEvent(QMouseEvent *event);
    void mouseReleaseEvent(QMouseEvent *event);
    void mouseDoubleClickEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
    void contextMenuEvent(QContextMenuEvent *event);
    void paintEvent (QPaintEvent *event);

private:
    typedef struct _StackItem {
        QString text;
        int ctx;
    } StackItem;

    int temporary_ctx_;
    QList<StackItem> labels_;
    bool shrinkable_;
    QElapsedTimer temporary_epoch_;
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
