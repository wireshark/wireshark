/* label_stack.h
 *
 * $Id: mainStatus_bar.cpp 40378 2012-01-04 22:13:01Z gerald $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef LABEL_STACK_H
#define LABEL_STACK_H

#include <QLabel>
#include <QStack>

class LabelStack : public QLabel
{
    Q_OBJECT
public:
    explicit LabelStack(QWidget *parent = 0);
    void setTemporaryContext(int ctx);
    void pushText(QString &text, int ctx);

private:
    typedef struct _StackItem {
        QString text;
        int ctx;
    } StackItem;

    int m_temporaryCtx;
    QList<StackItem *> m_labels;

    void fillLabel();

signals:

public slots:
    void popText(int ctx);

private slots:
    void popTemporaryText();
};

#endif // LABEL_STACK_H
