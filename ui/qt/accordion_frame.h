/* accordion_frame.cpp
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
