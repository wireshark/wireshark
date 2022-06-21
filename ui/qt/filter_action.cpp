/* filter_action.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "filter_action.h"

#include <ui/qt/main_application.h>
#include <ui/qt/main_window.h>

#include <QClipboard>
#include <QMenu>

FilterAction::FilterAction(QObject *parent, FilterAction::Action action, FilterAction::ActionType type, QString actionName) :
    QAction(parent),
    action_(action),
    type_(type),
    actionName_(actionName)
{
    setText(actionName);
}

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
        return QObject::tr("Prepare as Filter");
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
        return QObject::tr("…and Selected");
        break;
    case ActionTypeOr:
        return QObject::tr("…or Selected");
        break;
    case ActionTypeAndNot:
        return QObject::tr("…and not Selected");
        break;
    case ActionTypeOrNot:
        return QObject::tr("…or not Selected");
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

QActionGroup * FilterAction::createFilterGroup(QString filter, bool prepare, bool enabled, QWidget * parent)
{
    if (filter.isEmpty())
        enabled = false;

    bool filterEmpty = false;
    if (mainApp)
    {
        QWidget * mainWin = mainApp->mainWindow();
        if (qobject_cast<MainWindow *>(mainWin))
            filterEmpty = qobject_cast<MainWindow *>(mainWin)->getFilter().isEmpty();
    }

    FilterAction * filterAction = new FilterAction(parent, prepare ? FilterAction::ActionPrepare : FilterAction::ActionApply);

    QActionGroup * group = new QActionGroup(parent);
    group->setProperty("filter", filter);
    group->setProperty("filterAction", prepare ? FilterAction::ActionPrepare : FilterAction::ActionApply);
    QAction * action = group->addAction(tr("Selected"));
    action->setProperty("filterType", FilterAction::ActionTypePlain);
    action = group->addAction(tr("Not Selected"));
    action->setProperty("filterType", FilterAction::ActionTypeNot);
    action = group->addAction(tr("…and Selected"));
    action->setProperty("filterType", FilterAction::ActionTypeAnd);
    action->setEnabled(!filterEmpty);
    action = group->addAction(tr("…or Selected"));
    action->setProperty("filterType", FilterAction::ActionTypeOr);
    action->setEnabled(!filterEmpty);
    action = group->addAction(tr("…and not Selected"));
    action->setProperty("filterType", FilterAction::ActionTypeAndNot);
    action->setEnabled(!filterEmpty);
    action = group->addAction(tr("…or not Selected"));
    action->setProperty("filterType", FilterAction::ActionTypeOrNot);
    action->setEnabled(!filterEmpty);
    group->setEnabled(enabled);
    if (! filter.isEmpty())
        connect(group, &QActionGroup::triggered, filterAction, &FilterAction::groupTriggered);

    return group;
}

QMenu * FilterAction::createFilterMenu(FilterAction::Action act, QString filter, bool enabled, QWidget * par)
{
    QString title = (act == FilterAction::ActionApply) ? QObject::tr("Apply as Filter") : QObject::tr("Prepare as Filter");
    bool prepare = (act == FilterAction::ActionApply) ? false : true;

    QMenu * submenu = new QMenu(title, par);
    if (filter.length() > 0)
    {
        int one_em = submenu->fontMetrics().height();
        QString prep_text = QString("%1: %2").arg(title).arg(filter);
        prep_text = submenu->fontMetrics().elidedText(prep_text, Qt::ElideRight, one_em * 40);
        QAction * comment = submenu->addAction(prep_text);
        comment->setEnabled(false);
        submenu->addSeparator();
    }
    QActionGroup * group = FilterAction::createFilterGroup(filter, prepare, enabled, par);
    submenu->addActions(group->actions());

    return submenu;
}

void FilterAction::groupTriggered(QAction * action)
{
    if (action && mainApp)
    {
        if (action->property("filterType").canConvert<FilterAction::ActionType>() &&
            sender()->property("filterAction").canConvert<FilterAction::Action>())
        {
            FilterAction::Action act = sender()->property("filterAction").value<FilterAction::Action>();
            FilterAction::ActionType type = action->property("filterType").value<FilterAction::ActionType>();
            QString filter = sender()->property("filter").toString();

            QWidget * mainWin = mainApp->mainWindow();
            if (qobject_cast<MainWindow *>(mainWin))
            {
                MainWindow * mw = qobject_cast<MainWindow *>(mainWin);
                mw->setDisplayFilter(filter, act, type);
            }
        }
    }
}

QAction * FilterAction::copyFilterAction(QString filter, QWidget *par)
{
    FilterAction * filterAction = new FilterAction(par, ActionCopy);
    QAction * action = new QAction(QObject::tr("Copy"), par);
    action->setProperty("filter", QVariant::fromValue(filter));
    connect(action, &QAction::triggered, filterAction, &FilterAction::copyActionTriggered);

    if (filter.isEmpty())
        action->setEnabled(false);

    return action;
}

void FilterAction::copyActionTriggered()
{
    QAction * sendAction = qobject_cast<QAction *>(sender());
    if (! sendAction)
        return;

    QString filter = sendAction->property("filter").toString();
    if (filter.length() > 0)
        mainApp->clipboard()->setText(filter);
}
