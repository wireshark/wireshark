/* copy_from_profile_menu.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COPY_FROM_PROFILE_MENU_H
#define COPY_FROM_PROFILE_MENU_H

#include <config.h>
#include <glib.h>

#include <QMenu>

class CopyFromProfileMenu : public QMenu
{
    Q_OBJECT

public:
    explicit CopyFromProfileMenu(QString filename, QWidget *parent = 0);
    ~CopyFromProfileMenu() { }

    bool haveProfiles();

private:
    void addSystemDefault();

    QString filename_;
    bool have_profiles_;
};

#endif // COPY_FROM_PROFILE_MENU_H
