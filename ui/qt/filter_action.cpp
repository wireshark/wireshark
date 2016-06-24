/* filter_action.cpp
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

#include "filter_action.h"

FilterAction::FilterAction(QObject *parent, FilterAction::Action action, FilterAction::ActionType type, FilterAction::ActionDirection direction) :
    QAction(parent),
    action_(action),
    type_(type),
    direction_(direction)
{
    setText(actionDirectionName(direction));
}

FilterAction::FilterAction(QObject *parent, FilterAction::Action action, FilterAction::ActionType type) :
    QAction(parent),
    action_(action),
    type_(type),
    direction_(ActionDirectionAToAny)
{
    setText(actionTypeName(type));
}

FilterAction::FilterAction(QObject *parent, FilterAction::Action action) :
    QAction(parent),
    action_(action),
    type_(ActionTypePlain),
    direction_(ActionDirectionAToAny)
{
    setText(actionName(action));
}

const QList<FilterAction::Action> FilterAction::actions() {
    static const QList<Action> actions_ = QList<Action>()
            << ActionApply
            << ActionPrepare
            << ActionFind
            << ActionColorize
            << ActionWebLookup
            << ActionCopy;
    return actions_;
}

const QString FilterAction::actionName(Action action) {
    switch (action) {
    case ActionApply:
        return QObject::tr("Apply as Filter");
        break;
    case ActionPrepare:
        return QObject::tr("Prepare a Filter");
        break;
    case ActionFind:
        return QObject::tr("Find");
        break;
    case ActionColorize:
        return QObject::tr("Colorize");
        break;
    case ActionWebLookup:
        return QObject::tr("Look Up");
        break;
    case ActionCopy:
        return QObject::tr("Copy");
        break;
    default:
        return QObject::tr("UNKNOWN");
        break;
    }
}


const QList<FilterAction::ActionType> FilterAction::actionTypes(Action filter_action)
{
    static const QList<ActionType> action_types_ = QList<ActionType>()
            << ActionTypePlain
            << ActionTypeNot
            << ActionTypeAnd
            << ActionTypeOr
            << ActionTypeAndNot
            << ActionTypeOrNot;

    static const QList<ActionType> simple_action_types_ = QList<ActionType>()
            << ActionTypePlain
            << ActionTypeNot;

    switch (filter_action) {
    case ActionFind:
    case ActionColorize:
        return simple_action_types_;
    default:
        break;
    }

    return action_types_;
}

const QString FilterAction::actionTypeName(ActionType type) {
    switch (type) {
    case ActionTypePlain:
        return QObject::tr("Selected");
        break;
    case ActionTypeNot:
        return QObject::tr("Not Selected");
        break;
    case ActionTypeAnd:
        return QObject::tr(UTF8_HORIZONTAL_ELLIPSIS "and Selected");
        break;
    case ActionTypeOr:
        return QObject::tr(UTF8_HORIZONTAL_ELLIPSIS "or Selected");
        break;
    case ActionTypeAndNot:
        return QObject::tr(UTF8_HORIZONTAL_ELLIPSIS "and not Selected");
        break;
    case ActionTypeOrNot:
        return QObject::tr(UTF8_HORIZONTAL_ELLIPSIS "or not Selected");
        break;
    default:
        return QObject::tr("UNKNOWN");
        break;
    }
}


const QList<FilterAction::ActionDirection> FilterAction::actionDirections()
{
    static const QList<FilterAction::ActionDirection> action_directions_ = QList<ActionDirection>()
            << ActionDirectionAToFromB
            << ActionDirectionAToB
            << ActionDirectionAFromB
            << ActionDirectionAToFromAny
            << ActionDirectionAToAny
            << ActionDirectionAFromAny
            << ActionDirectionAnyToFromB
            << ActionDirectionAnyToB
            << ActionDirectionAnyFromB;
    return action_directions_;
}

const QString FilterAction::actionDirectionName(ActionDirection direction) {
    switch (direction) {
    case ActionDirectionAToFromB:
        return QObject::tr("A " UTF8_LEFT_RIGHT_ARROW " B");
        break;
    case ActionDirectionAToB:
        return QObject::tr("A " UTF8_RIGHTWARDS_ARROW " B");
        break;
    case ActionDirectionAFromB:
        return QObject::tr("B " UTF8_RIGHTWARDS_ARROW " A");
        break;
    case ActionDirectionAToFromAny:
        return QObject::tr("A " UTF8_LEFT_RIGHT_ARROW " Any");
        break;
    case ActionDirectionAToAny:
        return QObject::tr("A " UTF8_RIGHTWARDS_ARROW " Any");
        break;
    case ActionDirectionAFromAny:
        return QObject::tr("Any " UTF8_RIGHTWARDS_ARROW " A");
        break;
    case ActionDirectionAnyToFromB:
        return QObject::tr("Any " UTF8_LEFT_RIGHT_ARROW " B");
        break;
    case ActionDirectionAnyToB:
        return QObject::tr("Any " UTF8_RIGHTWARDS_ARROW " B");
        break;
    case ActionDirectionAnyFromB:
        return QObject::tr("B " UTF8_RIGHTWARDS_ARROW " Any");
        break;
    default:
        return QObject::tr("UNKNOWN");
        break;
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
