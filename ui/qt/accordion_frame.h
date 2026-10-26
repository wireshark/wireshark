/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCORDION_FRAME_H
#define ACCORDION_FRAME_H

#include <QFrame>

class QPropertyAnimation;

/**
 * @brief A QFrame that shows and hides itself with a slide animation.
 */
class AccordionFrame : public QFrame
{
    Q_OBJECT
public:
    /**
     * @brief Create an AccordionFrame with the given parent.
     * @param parent The parent widget of the frame, or nullptr if it has no parent.
     */
    explicit AccordionFrame(QWidget *parent = 0);

    /**
     * @brief Show the frame with a slide-down animation.
     */
    void animatedShow();

    /**
     * @brief Hide the frame with a slide-up animation.
     */
    void animatedHide();

    /** @brief Reapply the stylesheet after a palette or style change. */
    void updateStyleSheet();

signals:
    /**
     * @brief Emitted when the frame's visibility changes.
     * @param visible true when the frame becomes visible; false when hidden.
     */
    void visibilityChanged(bool visible);

protected:
    /** @brief Emit visibilityChanged(false) when the frame is hidden. */
    virtual void hideEvent(QHideEvent *) override { emit visibilityChanged(false); }

    /** @brief Emit visibilityChanged(true) when the frame is shown. */
    virtual void showEvent(QShowEvent *) override { emit visibilityChanged(true); }

private:
    int frame_height_;           /**< Height measured by animatedShow(); only the end value of the show animation. */
    int design_max_height_;      /**< maximumHeight before the first animation or zoom step (the .ui value); -1 until read. */
    QPropertyAnimation *animation_; /**< Animation that drives the maximumHeight property. */

    /** @brief The height cap at the current zoom level. */
    int zoomedMaxHeight();

private slots:
    /**
     * @brief Finalise the state of the frame after an animation completes.
     */
    void animationFinished();

    /**
     * @brief Re-apply the height cap after a zoom step unless an animation is running.
     */
    void applyZoomedMaxHeight();
};

#endif // ACCORDION_FRAME_H
