/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SPLASH_OVERLAY_H
#define SPLASH_OVERLAY_H

#include <config.h>

#include "epan/register.h"

#include <QWidget>
#include <QElapsedTimer>

class QGraphicsOpacityEffect;
class QPropertyAnimation;

/**
 * @brief Updates the splash overlay with a new action and message.
 *
 * This function is called to update the state of the splash overlay,
 * which could be used to display different actions or messages to the user.
 *
 * @param action The type of action to perform on the splash overlay.
 * @param message A string message to display along with the action.
 * @param dummy A dummy parameter that is not used and can be ignored.
 */
void splash_update(register_action_e action, const char *message, void *dummy);

/**
 * @brief Semi-transparent overlay widget displayed during application startup
 *        while Wireshark's protocol and plugin registration is in progress.
 *
 * Progress text is updated via the C-linkage splash_update() callback, which
 * is declared a friend so it can call the private splashUpdate() method.
 */
class SplashOverlay : public QWidget
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the SplashOverlay and begins tracking registration progress.
     * @param parent Optional parent widget; the overlay sizes itself to fill the parent.
     */
    explicit SplashOverlay(QWidget *parent = 0);

    /**
     * @brief Destroys the SplashOverlay and releases animation resources.
     */
    ~SplashOverlay();

    /**
     * @brief Starts a fade-out animation; the widget is hidden when the animation completes.
     */
    void fadeOut();

protected:
    /**
     * @brief Renders the overlay background, progress bar, and status text.
     * @param event The paint event (unused; the full widget area is always repainted).
     */
    void paintEvent(QPaintEvent *event) override;

private:
    register_action_e last_action_;  /**< Most recent registration action category. */
    int               register_cur_; /**< Number of registration steps completed so far. */
    int               register_max_; /**< Total number of registration steps to complete. */
    QString           action_text_;    /**< Primary status line shown on the overlay (e.g. "Initialising dissectors"). */
    QString           action_subtext_; /**< Secondary status line shown below the primary text. */
    QElapsedTimer     elapsed_timer_;  /**< Timer used to throttle repaint frequency during registration. */

    QGraphicsOpacityEffect *opacity_effect_;  /**< Opacity effect applied to the widget for the fade-out animation. */
    QPropertyAnimation     *fade_animation_;  /**< Animation that drives the opacity from 1.0 to 0.0 during fadeOut(). */

    static SplashOverlay *instance_; /**< Singleton pointer used by the C-linkage splash_update() callback. */

    /**
     * @brief Updates the overlay's progress state and triggers a repaint.
     * @param action  The current registration action category.
     * @param message Status message string provided by the registration framework.
     */
    void splashUpdate(register_action_e action, const char *message);

    /**
     * @brief C-linkage callback registered with the Wireshark registration framework.
     *
     * Forwards calls to SplashOverlay::instance_->splashUpdate().
     *
     * @param action  Current registration action.
     * @param message Status message from the registration framework.
     * @param dummy   Unused user-data pointer.
     */
    friend void splash_update(register_action_e action, const char *message, void *dummy);
};

#endif // SPLASH_OVERLAY_H
