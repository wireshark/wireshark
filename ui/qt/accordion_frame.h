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

class AccordionFrame : public QFrame
{
    Q_OBJECT
public:
    explicit AccordionFrame(QWidget *parent = 0);
    void animatedShow();
    void animatedHide();
    void updateStyleSheet();

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
