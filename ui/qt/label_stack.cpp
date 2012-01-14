/* label_stack.cpp
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

#include "label_stack.h"

#include <QTimer>

/* Temporary message timeouts */
#define TEMPORARY_MSG_TIMEOUT (7 * 1000)
//#define TEMPORARY_FLASH_TIMEOUT (1 * 1000)
//#define TEMPORARY_FLASH_INTERVAL (TEMPORARY_FLASH_TIMEOUT / 4)

LabelStack::LabelStack(QWidget *parent) :
    QLabel(parent)
{
    m_temporaryCtx = -1;
    fillLabel();
}

void LabelStack::setTemporaryContext(int ctx) {
    m_temporaryCtx = ctx;
}

void LabelStack::fillLabel() {
    StackItem *si;

    setStyleSheet(
            "QLabel {"
            "  margin-left: 0.5em;"
            "}"
            );

    if (m_labels.isEmpty()) {
        clear();
        return;
    }

    si = m_labels.first();

    if (si->ctx == m_temporaryCtx) {
        setStyleSheet(
                // Tango "Scarlet Red"
                "QLabel {"
                "  margin-left: 0.5em;"
                "  border-radius: 3px;"
                "  color: white;"
                "  background-color: rgba(239, 41, 41, 128);"
                "}"
                );
    }

    setText(si->text);
}

void LabelStack::pushText(QString &text, int ctx) {
    StackItem *si = new StackItem;
    si->text = text;
    si->ctx = ctx;
    m_labels.prepend(si);

    if (ctx == m_temporaryCtx) {
        QTimer::singleShot(TEMPORARY_MSG_TIMEOUT, this, SLOT(popTemporaryText()));
    }

    fillLabel();
}

void LabelStack::popText(int ctx) {
    QMutableListIterator<StackItem *> iter(m_labels);

    while (iter.hasNext()) {
        if (iter.next()->ctx == ctx) {
            iter.remove();
            break;
        }
    }

    fillLabel();
}

void LabelStack::popTemporaryText() {
    popText(m_temporaryCtx);
}
