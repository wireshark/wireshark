/* accordion_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "accordion_frame.h"

#include "ui/util.h"
#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/zoom_scaling.h>
#include <ui/qt/utils/theme_manager.h>

#include <QLayout>
#include <QPropertyAnimation>

const int duration_ = 150;

AccordionFrame::AccordionFrame(QWidget *parent) :
    QFrame(parent),
    frame_height_(0),
    design_max_height_(-1)
{
    updateStyleSheet();
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &AccordionFrame::updateStyleSheet);

    animation_ = new QPropertyAnimation(this, "maximumHeight", this);
    animation_->setDuration(duration_);
    animation_->setEasingCurve(QEasingCurve::InOutQuad);
    connect(animation_, &QPropertyAnimation::finished, this, &AccordionFrame::animationFinished);
    connect(FontManager::instance(), &FontManager::zoomChanged,
            this, &AccordionFrame::applyZoomedMaxHeight);
}

int AccordionFrame::zoomedMaxHeight()
{
    // Subclasses set their .ui size limits after this class's constructor,
    // and the animations below overwrite maximumHeight, so the design cap is
    // read once, before the first animation or zoom step writes it.
    if (design_max_height_ < 0) {
        design_max_height_ = maximumHeight();
    }
    return ZoomScaling::scaledSizeLimit(design_max_height_);
}

void AccordionFrame::applyZoomedMaxHeight()
{
    // animationFinished() applies the cap when a running animation ends.
    if (animation_->state() == QAbstractAnimation::Running) {
        return;
    }
    setMaximumHeight(zoomedMaxHeight());
}

void AccordionFrame::animatedShow()
{
    if (isVisible()) {
        show();
        return;
    }

    // A previous animation can leave maximumHeight at an old measured
    // height, which is too small after a zoom in. Measure under the cap.
    setMaximumHeight(zoomedMaxHeight());

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
        animation_->setStartValue(height());
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
    }
    // After a show the measured height must not stay the cap, or the frame
    // cannot grow with later font or zoom changes.
    setMaximumHeight(zoomedMaxHeight());
}

void AccordionFrame::updateStyleSheet()
{
    setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/accordion-frame")));
}
