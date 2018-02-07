/* preference_manager.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREFERENCE_MANAGER_H
#define PREFERENCE_MANAGER_H

#include <config.h>

#include <QObject>
#include <QMetaObject>
#include <QHash>
#include <QActionGroup>

#include <ui/qt/models/pref_models.h>
#include <ui/qt/capture_file.h>

class PreferenceFactory;
class WiresharkPreference;

class PreferenceManager : public QObject
{
    Q_OBJECT

public:
    static PreferenceManager* instance();
    virtual ~PreferenceManager();

    void registerType(int pref, PreferenceFactory * factory);
    void reuseType(int pref, int reuseFor);
    WiresharkPreference * getPreference(PrefsItem * item);

protected:
    explicit PreferenceManager(QObject * parent = Q_NULLPTR);

private:
    static QMap<int, PreferenceFactory*> & factories();
};

class PreferenceFactory : public QObject
{
    Q_OBJECT
public:
    virtual ~PreferenceFactory();
    virtual WiresharkPreference * create(QObject * parent = Q_NULLPTR) = 0;
};

#define REGISTER_PREFERENCE_TYPE(pref_id, preference_class) \
    class preference_class##pref_id##Factory : public PreferenceFactory { \
    public: \
        preference_class##pref_id##Factory() \
        { \
            PreferenceManager::instance()->registerType(pref_id, this); \
        } \
        virtual WiresharkPreference *create(QObject * parent) { \
            WiresharkPreference * newPrefHandler = new preference_class(parent); \
            return newPrefHandler; \
        } \
    }; \
    static preference_class##pref_id##Factory global_##preference_class##pref_id##Factory;

#endif // PREFERENCE_MANAGER_H

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
