/* preference_manager.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/manager/preference_manager.h>
#include <ui/qt/manager/wireshark_preference.h>

#include <QMetaMethod>

PreferenceFactory::~PreferenceFactory() {}

QMap<int, PreferenceFactory *> & PreferenceManager::factories()
{
    static QMap<int, PreferenceFactory *> inst = QMap<int, PreferenceFactory *>();
    return inst;
}

PreferenceManager::PreferenceManager(QObject * parent)
    : QObject(parent)
{}

PreferenceManager::~PreferenceManager()
{
    /* As this is a singleton, this is the point, where we can clear the registry */
    PreferenceManager::factories().clear();
}

PreferenceManager * PreferenceManager::instance()
{
    static PreferenceManager* _inst = 0;
    if (! _inst)
        _inst = new PreferenceManager();

    return _inst;
}

void PreferenceManager::registerType(int pref, PreferenceFactory * factory)
{
    Q_ASSERT(pref >= 0);

    if (PreferenceManager::factories().contains(pref) || ! factory)
        return;

    PreferenceManager::factories()[pref] = factory;
}

WiresharkPreference * PreferenceManager::getPreference(PrefsItem * pref)
{
    if (! pref)
        return Q_NULLPTR;

    int key = pref->getPrefType();
    if (! PreferenceManager::factories().contains(key))
        return Q_NULLPTR;

    /* All actions are parented with this manager, to clear the objects together with the manager */
    WiresharkPreference * wspref = qobject_cast<WiresharkPreference *>(PreferenceManager::factories()[key]->create(this));
    if (wspref)
        wspref->setPrefsItem(pref);

    return wspref;
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
