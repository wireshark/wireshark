/* copy_from_profile_button.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COPY_FROM_PROFILE_BUTTON_H
#define COPY_FROM_PROFILE_BUTTON_H

#include <config.h>
#include <glib.h>

#include <QPushButton>

class QMenu;

class CopyFromProfileButton : public QPushButton
{
    Q_OBJECT

public:
    explicit CopyFromProfileButton(QString filename);
    ~CopyFromProfileButton() { }

private:
    void addSystemDefault();

    QMenu *menu_;
    QString filename_;
};

#endif // COPY_FROM_PROFILE_BUTTON_H
