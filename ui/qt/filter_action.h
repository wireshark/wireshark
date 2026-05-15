/** @file
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
#include <QActionGroup>

/**
 * @brief An action that applies, prepares, or modifies a display filter.
 */
class FilterAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Defines an action to be taken with a filter.
     */
    enum Action {
        ActionApply,     /**< Apply the filter immediately. */
        ActionColorize,  /**< Use the filter for colorization rules. */
        ActionCopy,      /**< Copy the filter string to the clipboard. */
        ActionFind,      /**< Use the filter in a find operation. */
        ActionPrepare,   /**< Prepare the filter but do not apply it yet. */
        ActionWebLookup  /**< Look up information related to the filter on the web. */
    };
    Q_ENUM(Action)

    /**
     * @brief Defines how the new filter should be combined with the existing one.
     */
    enum ActionType {
        ActionTypePlain,   /**< Replace the existing filter. */
        ActionTypeNot,     /**< Negate the current filter. */
        ActionTypeAnd,     /**< Combine with existing filter using logical AND. */
        ActionTypeOr,      /**< Combine with existing filter using logical OR. */
        ActionTypeAndNot,  /**< Combine using logical AND NOT. */
        ActionTypeOrNot    /**< Combine using logical OR NOT. */
    };
    Q_ENUM(ActionType)

    /**
     * @brief Defines the directionality aspect of the filter.
     */
    enum ActionDirection {
        ActionDirectionAToFromB,  /**< Bidirectional communication between A and B. */
        ActionDirectionAToB,      /**< Communication from A to B. */
        ActionDirectionAFromB,    /**< Communication to A from B. */
        ActionDirectionAToFromAny,/**< Bidirectional communication between A and any host. */
        ActionDirectionAToAny,    /**< Communication from A to any host. */
        ActionDirectionAFromAny,  /**< Communication to A from any host. */
        ActionDirectionAnyToFromB,/**< Bidirectional communication between any host and B. */
        ActionDirectionAnyToB,    /**< Communication from any host to B. */
        ActionDirectionAnyFromB   /**< Communication to any host from B. */
    };

    /**
     * @brief Constructs a FilterAction with a specific name.
     * @param parent The parent QObject.
     * @param action The primary action type.
     * @param type The logical combination type.
     * @param actionName The custom name for the action.
     */
    explicit FilterAction(QObject *parent, Action action, ActionType type, QString actionName);

    /**
     * @brief Constructs a FilterAction specifying a direction.
     * @param parent The parent QObject.
     * @param action The primary action type.
     * @param type The logical combination type.
     * @param direction The directionality of the filter.
     */
    explicit FilterAction(QObject *parent, Action action, ActionType type, ActionDirection direction);

    /**
     * @brief Constructs a FilterAction with a specific action and type.
     * @param parent The parent QObject.
     * @param action The primary action type.
     * @param type The logical combination type.
     */
    explicit FilterAction(QObject *parent, Action action, ActionType type);

    /**
     * @brief Constructs a basic FilterAction.
     * @param parent The parent QObject.
     * @param action The primary action type.
     */
    explicit FilterAction(QObject *parent, Action action);

    /**
     * @brief Retrieves the primary action.
     * @return The configured Action.
     */
    Action action() { return action_; }

    /**
     * @brief Retrieves a list of all available primary actions.
     * @return A list of Action enumerations.
     */
    static const QList<Action> actions();

    /**
     * @brief Retrieves the string name of a specific action.
     * @param action The action enumeration.
     * @return The name string.
     */
    static const QString actionName(Action action);

    /**
     * @brief Retrieves the logical action type.
     * @return The configured ActionType.
     */
    ActionType actionType() { return type_; }

    /**
     * @brief Retrieves a list of available action types for a given primary action.
     * @param filter_action The primary action context (defaults to ActionApply).
     * @return A list of ActionType enumerations.
     */
    static const QList<ActionType> actionTypes(Action filter_action = ActionApply);

    /**
     * @brief Retrieves the string name of a specific action type.
     * @param type The action type enumeration.
     * @return The name string.
     */
    static const QString actionTypeName(ActionType type);

    /**
     * @brief Retrieves the action direction.
     * @return The configured ActionDirection.
     */
    ActionDirection actionDirection() { return direction_; }

    /**
     * @brief Retrieves a list of all available action directions.
     * @return A list of ActionDirection enumerations.
     */
    static const QList<ActionDirection> actionDirections();

    /**
     * @brief Retrieves the string name of a specific action direction.
     * @param direction The action direction enumeration.
     * @return The name string.
     */
    static const QString actionDirectionName(ActionDirection direction);

    /**
     * @brief Creates an action group containing standard filter operations.
     * @param filter The base filter string.
     * @param prepare True to only prepare the filter, false to apply it.
     * @param enabled True if the actions should be enabled.
     * @param parent The parent widget.
     * @return A pointer to the created QActionGroup.
     */
    static QActionGroup * createFilterGroup(QString filter, bool prepare, bool enabled, QWidget * parent);

    /**
     * @brief Creates a context menu containing standard filter operations.
     * @param act The primary action context.
     * @param filter The base filter string.
     * @param enabled True if the menu items should be enabled.
     * @param parent The parent widget.
     * @return A pointer to the created QMenu.
     */
    static QMenu * createFilterMenu(FilterAction::Action act, QString filter, bool enabled, QWidget * parent);

    /**
     * @brief Creates an action specifically to copy a filter string.
     * @param filter The filter string to copy.
     * @param par The parent widget.
     * @return A pointer to the created QAction.
     */
    static QAction * copyFilterAction(QString filter, QWidget *par);

signals:

public slots:

private:
    /** The primary action to perform. */
    Action action_;

    /** The logical combination type. */
    ActionType type_;

    /** The directionality of the filter. */
    ActionDirection direction_;

    /** The custom name of the action. */
    QString actionName_;

private slots:
    /**
     * @brief Slot triggered when any action in an associated group is activated.
     * @param action The specific action that was triggered.
     */
    void groupTriggered(QAction *action);

    /**
     * @brief Slot triggered to perform a copy operation.
     */
    void copyActionTriggered();

};

#endif // FILTER_ACTION_H
