/* filter_action.h
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

/* Derived from gtk/filter_utils.h */

#ifndef FILTER_ACTION_H
#define FILTER_ACTION_H

#include <wsutil/utf8_entities.h>

#include <QAction>

class FilterAction : public QAction
{
    Q_OBJECT
public:
    /* Filter actions */
    enum Action {
        ActionApply,
        ActionColorize,
        ActionCopy,
        ActionFind,
        ActionPrepare,
        ActionWebLookup
    };

    /* Action type - says what to do with the filter */
    enum ActionType {
        ActionTypePlain,
        ActionTypeNot,
        ActionTypeAnd,
        ActionTypeOr,
        ActionTypeAndNot,
        ActionTypeOrNot
    };

    /* Action direction */
    enum ActionDirection {
        ActionDirectionAToFromB,
        ActionDirectionAToB,
        ActionDirectionAFromB,
        ActionDirectionAToFromAny,
        ActionDirectionAToAny,
        ActionDirectionAFromAny,
        ActionDirectionAnyToFromB,
        ActionDirectionAnyToB,
        ActionDirectionAnyFromB
    };

    explicit FilterAction(QObject *parent, Action action, ActionType type, ActionDirection direction);
    explicit FilterAction(QObject *parent, Action action, ActionType type);
    explicit FilterAction(QObject *parent, Action action);

    Action action() { return action_; }
    static const QList<Action> actions();
    static const QString actionName(Action action);

    ActionType actionType() { return type_; }
    static const QList<ActionType> actionTypes(Action filter_action = ActionApply);
    static const QString actionTypeName(ActionType type);

    ActionDirection actionDirection() { return direction_; }
    static const QList<ActionDirection> actionDirections();
    static const QString actionDirectionName(ActionDirection direction);

signals:

public slots:

private:
    Action action_;
    ActionType type_;
    ActionDirection direction_;

};

#endif // FILTER_ACTION_H

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
