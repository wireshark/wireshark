/** @file
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

/**
 * @brief Manages the registration and creation of Wireshark preferences.
 */
class PreferenceManager : public QObject
{
public:
    /**
     * @brief Retrieves the singleton instance of the PreferenceManager.
     * @return Pointer to the PreferenceManager instance.
     */
    static PreferenceManager* instance();

    /**
     * @brief Destroys the PreferenceManager.
     */
    virtual ~PreferenceManager();

    /**
     * @brief Registers a preference factory for a specific preference type.
     * @param pref The preference type identifier.
     * @param factory Pointer to the factory to register.
     */
    void registerType(int pref, PreferenceFactory * factory);

    /**
     * @brief Maps an existing preference factory to another preference type.
     * @param pref The preference type identifier of the existing factory.
     * @param reuseFor The new preference type identifier to map to the factory.
     */
    void reuseType(int pref, int reuseFor);

    /**
     * @brief Retrieves a WiresharkPreference instance for the given PrefsItem.
     * @param item Pointer to the PrefsItem to create a preference for.
     * @return Pointer to the created WiresharkPreference.
     */
    WiresharkPreference * getPreference(PrefsItem * item);

protected:
    /**
     * @brief Constructs a new PreferenceManager.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit PreferenceManager(QObject * parent = Q_NULLPTR);

private:
    /**
     * @brief Retrieves the static map of registered preference factories.
     * @return Reference to the map of preference types to PreferenceFactory pointers.
     */
    static QMap<int, PreferenceFactory*> & factories();
};

/**
 * @brief Abstract base class for creating Wireshark preference objects.
 */
class PreferenceFactory : public QObject
{
public:
    /**
     * @brief Destroys the PreferenceFactory.
     */
    virtual ~PreferenceFactory();

    /**
     * @brief Creates a new WiresharkPreference object.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     * @return Pointer to the newly created WiresharkPreference.
     */
    virtual WiresharkPreference * create(QObject * parent = Q_NULLPTR) = 0;
};

/**
 * @brief Macro to register a new preference type with its corresponding handler class.
 * @param pref_id The identifier for the preference type.
 * @param preference_class The class implementing the preference handling.
 */
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
