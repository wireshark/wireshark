/* accordion_frame.cpp
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

#ifndef ACCORDION_FRAME_H
#define ACCORDION_FRAME_H

#include <QFrame>

class QPropertyAnimation;

class AccordionFrame : public QFrame
{
    Q_OBJECT
public:
    explicit AccordionFrame(QWidget *parent = 0);
    void animatedShow();
    void animatedHide();

signals:
    void visibilityChanged(bool visible);

protected:
    virtual void hideEvent(QHideEvent *) { emit visibilityChanged(false); }
    virtual void showEvent(QShowEvent *) { emit visibilityChanged(true); }

private:
    int frame_height_;
    QPropertyAnimation *animation_;

private slots:
    void animationFinished();

};

#endif // ACCORDION_FRAME_H

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
