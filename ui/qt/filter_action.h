/* filter_action.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
