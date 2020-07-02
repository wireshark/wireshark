/* protocol_preferences_menu.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/proto.h>

#include <ui/preference_utils.h>
#include <wsutil/utf8_entities.h>

#include "protocol_preferences_menu.h"

#include <ui/qt/models/enabled_protocols_model.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "uat_dialog.h"
#include "wireshark_application.h"

// To do:
// - Elide really long items?
// - Handle color prefs.

class BoolPreferenceAction : public QAction
{
public:
    BoolPreferenceAction(pref_t *pref, QObject *parent=0) :
        QAction(parent),
        pref_(pref)
    {
        setText(prefs_get_title(pref_));
        setCheckable(true);
        setChecked(prefs_get_bool_value(pref_, pref_current));
    }

    unsigned int setBoolValue() {
        return prefs_set_bool_value(pref_, isChecked(), pref_current);
    }

private:
    pref_t *pref_;
};

class EnumPreferenceAction : public QAction
{
public:
    EnumPreferenceAction(pref_t *pref, const char *title, int enumval, QActionGroup *ag, QObject *parent=0) :
        QAction(parent),
        pref_(pref),
        enumval_(enumval)
    {
        setText(title);
        setActionGroup(ag);
        setCheckable(true);
    }

    unsigned int setEnumValue() {
        return prefs_set_enum_value(pref_, enumval_, pref_current);
    }

private:
    pref_t *pref_;
    int enumval_;
};

class UatPreferenceAction : public QAction
{
public:
    UatPreferenceAction(pref_t *pref, QObject *parent=0) :
        QAction(parent),
        pref_(pref)
    {
        setText(QString("%1" UTF8_HORIZONTAL_ELLIPSIS).arg(prefs_get_title(pref_)));
    }

    void showUatDialog() {
        UatDialog *uat_dlg = new UatDialog(parentWidget(), prefs_get_uat_value(pref_));
        connect(uat_dlg, SIGNAL(destroyed(QObject*)), wsApp, SLOT(flushAppSignals()));
        uat_dlg->setWindowModality(Qt::ApplicationModal);
        uat_dlg->setAttribute(Qt::WA_DeleteOnClose);
        uat_dlg->show();
    }

private:
    pref_t *pref_;
};

// Preference requires an external editor (PreferenceEditorFrame)
class EditorPreferenceAction : public QAction
{
public:
    EditorPreferenceAction(pref_t *pref, QObject *parent=0) :
        QAction(parent),
        pref_(pref)
    {
        QString title = prefs_get_title(pref_);

        title.append(QString(": %1" UTF8_HORIZONTAL_ELLIPSIS).arg(gchar_free_to_qstring(prefs_pref_to_str(pref_, pref_current))));

        setText(title);
    }
    pref_t *pref() { return pref_; }

private:
    pref_t *pref_;
};

extern "C" {
// Preference callback

static guint
add_prefs_menu_item(pref_t *pref, gpointer menu_ptr)
{
    ProtocolPreferencesMenu *pp_menu = static_cast<ProtocolPreferencesMenu *>(menu_ptr);
    if (!pp_menu) return 1;

    pp_menu->addMenuItem(pref);

    return 0;
}
}


ProtocolPreferencesMenu::ProtocolPreferencesMenu()
{
    setTitle(tr("Protocol Preferences"));
    setModule(NULL);
}

ProtocolPreferencesMenu::ProtocolPreferencesMenu(const QString &title, const QString &module_name, QWidget *parent) :
    QMenu(title, parent)
{
    setModule(module_name);
}

void ProtocolPreferencesMenu::setModule(const QString module_name)
{
    QAction *action;
    int proto_id = -1;

    if (!module_name.isEmpty()) {
        proto_id = proto_get_id_by_filter_name(module_name.toUtf8().constData());
    }

    clear();
    module_name_.clear();
    module_ = NULL;

    protocol_ = find_protocol_by_id(proto_id);
    const QString long_name = proto_get_protocol_long_name(protocol_);
    const QString short_name = proto_get_protocol_short_name(protocol_);
    if (module_name.isEmpty() || proto_id < 0 || !protocol_) {
        action = addAction(tr("No protocol preferences available"));
        action->setDisabled(true);
        return;
    }

    QAction *disable_action = new QAction(tr("Disable %1").arg(short_name), this);
    connect(disable_action, SIGNAL(triggered(bool)), this, SLOT(disableProtocolTriggered()));
    disable_action->setDisabled(!proto_can_toggle_protocol(proto_id));

    module_ = prefs_find_module(module_name.toUtf8().constData());
    if (!module_ || !prefs_is_registered_protocol(module_name.toUtf8().constData())) {
        action = addAction(tr("%1 has no preferences").arg(long_name));
        action->setDisabled(true);
        addSeparator();
        addAction(disable_action);
        return;
    }

    module_name_ = module_name;

    action = addAction(tr("Open %1 preferences" UTF8_HORIZONTAL_ELLIPSIS).arg(long_name));
    action->setData(QString(module_name));
    connect(action, SIGNAL(triggered(bool)), this, SLOT(modulePreferencesTriggered()));
    addSeparator();

    prefs_pref_foreach(module_, add_prefs_menu_item, this);

    if (!actions().last()->isSeparator()) {
        addSeparator();
    }
    addAction(disable_action);
}

void ProtocolPreferencesMenu::addMenuItem(preference *pref)
{
    switch (prefs_get_type(pref)) {
    case PREF_BOOL:
    {
        BoolPreferenceAction *bpa = new BoolPreferenceAction(pref, this);
        addAction(bpa);
        connect(bpa, SIGNAL(triggered(bool)), this, SLOT(boolPreferenceTriggered()));
        break;
    }
    case PREF_ENUM:
    {
        QMenu *enum_menu = addMenu(prefs_get_title(pref));
        const enum_val_t *enum_valp = prefs_get_enumvals(pref);
        if (enum_valp && enum_valp->name) {
            QActionGroup *ag = new QActionGroup(this);
            while (enum_valp->name) {
                EnumPreferenceAction *epa = new EnumPreferenceAction(pref, enum_valp->description, enum_valp->value, ag, this);
                if (prefs_get_enum_value(pref, pref_current) == enum_valp->value) {
                    epa->setChecked(true);
                }
                enum_menu->addAction(epa);
                connect(epa, SIGNAL(triggered(bool)), this, SLOT(enumPreferenceTriggered()));
                enum_valp++;
            }
        }
        break;
    }
    case PREF_UINT:
    case PREF_STRING:
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    case PREF_RANGE:
    case PREF_DECODE_AS_UINT:
    case PREF_DECODE_AS_RANGE:
    {
        EditorPreferenceAction *epa = new EditorPreferenceAction(pref, this);
        addAction(epa);
        connect(epa, SIGNAL(triggered(bool)), this, SLOT(editorPreferenceTriggered()));
        break;
    }
    case PREF_UAT:
    {
        UatPreferenceAction *upa = new UatPreferenceAction(pref, this);
        addAction(upa);
        connect(upa, SIGNAL(triggered(bool)), this, SLOT(uatPreferenceTriggered()));
        break;
    }
    case PREF_CUSTOM:
    case PREF_STATIC_TEXT:
    case PREF_OBSOLETE:
        break;
    default:
        // A type we currently don't handle. Just open the prefs dialog.
        QString title = QString("%1" UTF8_HORIZONTAL_ELLIPSIS).arg(prefs_get_title(pref));
        QAction *mpa = addAction(title);
        connect(mpa, SIGNAL(triggered(bool)), this, SLOT(modulePreferencesTriggered()));
        break;
    }
}

void ProtocolPreferencesMenu::disableProtocolTriggered()
{
    EnabledProtocolsModel::disableProtocol(protocol_);
}

void ProtocolPreferencesMenu::modulePreferencesTriggered()
{
    if (!module_name_.isEmpty()) {
        emit showProtocolPreferences(module_name_);
    }
}

void ProtocolPreferencesMenu::editorPreferenceTriggered()
{
    EditorPreferenceAction *epa = static_cast<EditorPreferenceAction *>(QObject::sender());
    if (!epa) return;

    if (epa->pref() && module_) {
        emit editProtocolPreference(epa->pref(), module_);
    }
}

void ProtocolPreferencesMenu::boolPreferenceTriggered()
{
    BoolPreferenceAction *bpa = static_cast<BoolPreferenceAction *>(QObject::sender());
    if (!bpa) return;

    module_->prefs_changed_flags |= bpa->setBoolValue();
    unsigned int changed_flags = module_->prefs_changed_flags;

    prefs_apply(module_);
    prefs_main_write();

    if (changed_flags & PREF_EFFECT_FIELDS) {
        wsApp->emitAppSignal(WiresharkApplication::FieldsChanged);
    }
    /* Protocol preference changes almost always affect dissection,
       so don't bother checking flags */
    wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void ProtocolPreferencesMenu::enumPreferenceTriggered()
{
    EnumPreferenceAction *epa = static_cast<EnumPreferenceAction *>(QObject::sender());
    if (!epa) return;

    unsigned int changed_flags = epa->setEnumValue();
    if (changed_flags) { // Changed
        module_->prefs_changed_flags |= changed_flags;
        prefs_apply(module_);
        prefs_main_write();

        if (changed_flags & PREF_EFFECT_FIELDS) {
            wsApp->emitAppSignal(WiresharkApplication::FieldsChanged);
        }
        /* Protocol preference changes almost always affect dissection,
           so don't bother checking flags */
        wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
    }
}

void ProtocolPreferencesMenu::uatPreferenceTriggered()
{
    UatPreferenceAction *upa = static_cast<UatPreferenceAction *>(QObject::sender());
    if (!upa) return;

    upa->showUatDialog();
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
