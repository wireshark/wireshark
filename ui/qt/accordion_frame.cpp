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

#include <QLayout>
#include <QPropertyAnimation>

const int duration_ = 150;

AccordionFrame::AccordionFrame(QWidget *parent) :
    QFrame(parent),
    frame_height_(0)
{
    QString subframe_style(
//                ".QFrame {"
//                "  background: palette(window);"
//                "  padding-top: 0.1em;"
//                "  padding-bottom: 0.1em;"
//                "  border-bottom: 1px solid palette(shadow);"
//                "}"
                "QLineEdit#goToLineEdit {"
                "  max-width: 5em;"
                "}"
                );
    setStyleSheet(subframe_style);
    animation_ = new QPropertyAnimation(this, "maximumHeight", this);
    animation_->setDuration(duration_);
    animation_->setEasingCurve(QEasingCurve::InOutQuad);
    connect(animation_, SIGNAL(finished()), this, SLOT(animationFinished()));
}

void AccordionFrame::animatedShow()
{
    if (isVisible()) {
        show();
        return;
    }

    if (!display_is_remote()) {
        QWidget *parent = parentWidget();

        if (parent && parent->layout()) {
            // Force our parent layout to update its geometry. There are a number
            // of ways of doing this. Calling invalidate + activate seems to
            // be the best.
            show();
            parent->layout()->invalidate(); // Calls parent->layout()->update()
            parent->layout()->activate(); // Calculates sizes then calls parent->updateGeometry()
            frame_height_ = height();
            hide();
        }
        if (frame_height_ > 0) {
            animation_->setStartValue(0);
            animation_->setEndValue(frame_height_);
            animation_->start();
        }
    }
    show();
}

void AccordionFrame::animatedHide()
{
    if (!isVisible()) {
        hide();
        return;
    }

    if (!display_is_remote()) {
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
