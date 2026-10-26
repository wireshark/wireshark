/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UNIQUE_NAME_H
#define UNIQUE_NAME_H

#include <QString>

/**
 * Returns the first name candidate(0), candidate(1), ... that @p isTaken
 * rejects.  candidate(0) is the preferred name; later indexes add a
 * counter in the caller's style ("theme-2", "name (copy 1)").
 *
 * @param candidate  callable taking an int and returning a QString.
 * @param isTaken    callable taking a const QString & and returning true
 *                   when that name is in use.
 */
template <typename Candidate, typename IsTaken>
QString uniqueName(Candidate candidate, IsTaken isTaken)
{
    for (int n = 0; ; ++n) {
        QString name = candidate(n);
        if (!isTaken(name))
            return name;
    }
}

#endif // UNIQUE_NAME_H
