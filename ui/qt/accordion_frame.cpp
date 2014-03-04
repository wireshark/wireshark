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


#include "config.h"
#include <glib.h>

#include "accordion_frame.h"

#include "ui/util.h"

const int duration_ = 150;

AccordionFrame::AccordionFrame(QWidget *parent) :
    QFrame(parent)
{
    QString subframe_style(
                ".QFrame {"
                "  background: palette(window);"
                "  padding-top: 0.1em;"
                "  padding-bottom: 0.1em;"
                "  border-bottom: 1px solid palette(shadow);"
                "}"
                "QLineEdit#goToLineEdit {"
                "  max-width: 5em;"
                "}"
                );
    setStyleSheet(subframe_style);
    frame_height_ = height();
    animation_ = new QPropertyAnimation(this, "maximumHeight");
    animation_->setDuration(duration_);
    animation_->setEasingCurve(QEasingCurve::InOutQuad);
    connect(animation_, SIGNAL(finished()), this, SLOT(animationFinished()));
}

void AccordionFrame::animatedShow()
{
    if (strlen (get_conn_cfilter()) < 1) {
        animation_->setStartValue(0);
        animation_->setEndValue(frame_height_);
        animation_->start();
    }
    show();
}

void AccordionFrame::animatedHide()
{
    if (strlen (get_conn_cfilter()) < 1) {
        animation_->setStartValue(frame_height_);
        animation_->setEndValue(0);
        animation_->start();
    } else {
        hide();
    }
}

void AccordionFrame::animationFinished()
{
    if (animation_->currentValue().toInt() < 1) {
        hide();
        setMaximumHeight(frame_height_);
    }
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
