/* protocol_preferences_menu.h
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

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/proto.h>

#include <ui/preference_utils.h>
#include <wsutil/utf8_entities.h>

#include "protocol_preferences_menu.h"

#include "enabled_protocols_dialog.h"
#include "qt_ui_utils.h"
#include "uat_dialog.h"
#include "wireshark_application.h"

// To do:
// - Elide really long items?
// - Handle PREF_FILENAME and PREF_DIRNAME.
// - Handle color prefs.

class BoolPreferenceAction : public QAction
{
public:
    BoolPreferenceAction(pref_t *pref) :
        QAction(NULL),
        pref_(pref)
    {
        setText(pref_->title);
        setCheckable(true);
        setChecked(*pref->varp.boolp);
    }

    void setBoolValue() {
        *pref_->varp.boolp = isChecked();
    }

private:
    pref_t *pref_;
};

class EnumPreferenceAction : public QAction
{
public:
    EnumPreferenceAction(pref_t *pref, const char *title, int enumval, QActionGroup *ag) :
        QAction(NULL),
        pref_(pref),
        enumval_(enumval)
    {
        setText(title);
        setActionGroup(ag);
        setCheckable(true);
    }

    bool setEnumValue() {
        if (*pref_->varp.enump != enumval_) {
            *pref_->varp.enump = enumval_;
            return true;
        }
        return false;
    }

private:
    pref_t *pref_;
    int enumval_;
};

class UatPreferenceAction : public QAction
{
public:
    UatPreferenceAction(pref_t *pref) :
        QAction(NULL),
        pref_(pref)
    {
        setText(QString("%1" UTF8_HORIZONTAL_ELLIPSIS).arg(pref_->title));
    }

    void showUatDialog() {
        UatDialog uat_dlg(parentWidget(), pref_->varp.uat);
        uat_dlg.exec();
        // Emitting PacketDissectionChanged directly from a QDialog can cause
        // problems on OS X.
        wsApp->flushAppSignals();
    }

private:
    pref_t *pref_;
};

// Preference requires an external editor (PreferenceEditorFrame)
class EditorPreferenceAction : public QAction
{
public:
    EditorPreferenceAction(pref_t *pref) :
        QAction(NULL),
        pref_(pref)
    {
        QString title = pref_->title;

        switch(pref_->type) {
        case PREF_UINT:
        {
            int base = 10;
            switch(pref_->info.base) {
            case 8:
                base = 8;
                break;
            case 16:
                base = 16;
                break;
            default:
                break;
            }
            title.append(QString(": %1" UTF8_HORIZONTAL_ELLIPSIS).arg(QString::number(*pref->varp.uint, base)));
            break;
        }
        case PREF_STRING:
            title.append(QString(": %1" UTF8_HORIZONTAL_ELLIPSIS).arg(*pref->varp.string));
            break;
        case PREF_RANGE:
            title.append(QString(": %1" UTF8_HORIZONTAL_ELLIPSIS).arg(range_to_qstring(*pref->varp.range)));
            break;
        default:
            // We shouldn't be here.
            break;
        }

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

void ProtocolPreferencesMenu::setModule(const char *module_name)
{
    QAction *action;
    int proto_id = -1;

    if (module_name) {
        proto_id = proto_get_id_by_filter_name(module_name);
    }

    clear();
    module_name_.clear();
    module_ = NULL;

    protocol_ = find_protocol_by_id(proto_id);
    const QString long_name = proto_get_protocol_long_name(protocol_);
    const QString short_name = proto_get_protocol_short_name(protocol_);
    if (!module_name || proto_id < 0 || !protocol_) {
        action = addAction(tr("No protocol preferences available"));
        action->setDisabled(true);
        return;
    }

    QAction *disable_action = new QAction(tr("Disable %1" UTF8_HORIZONTAL_ELLIPSIS).arg(short_name), this);
    connect(disable_action, SIGNAL(triggered(bool)), this, SLOT(disableProtocolTriggered()));

    module_ = prefs_find_module(module_name);
    if (!module_ || !prefs_is_registered_protocol(module_name)) {
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
    switch (pref->type) {
    case PREF_BOOL:
    {
        BoolPreferenceAction *bpa = new BoolPreferenceAction(pref);
        addAction(bpa);
        connect(bpa, SIGNAL(triggered(bool)), this, SLOT(boolPreferenceTriggered()));
        break;
    }
    case PREF_ENUM:
    {
        QActionGroup *ag = new QActionGroup(this);
        QMenu *enum_menu = addMenu(pref->title);
        for (const enum_val_t *enum_valp = pref->info.enum_info.enumvals; enum_valp->name; enum_valp++) {
            EnumPreferenceAction *epa = new EnumPreferenceAction(pref, enum_valp->description, enum_valp->value, ag);
            if (*pref->varp.enump == enum_valp->value) {
                epa->setChecked(true);
            }
            enum_menu->addAction(epa);
            connect(epa, SIGNAL(triggered(bool)), this, SLOT(enumPreferenceTriggered()));
        }
        break;
    }
    case PREF_UINT:
    case PREF_STRING:
    case PREF_RANGE:
    {
        EditorPreferenceAction *epa = new EditorPreferenceAction(pref);
        addAction(epa);
        connect(epa, SIGNAL(triggered(bool)), this, SLOT(editorPreferenceTriggered()));
        break;
    }
    case PREF_UAT:
    {
        UatPreferenceAction *upa = new UatPreferenceAction(pref);
        addAction(upa);
        connect(upa, SIGNAL(triggered(bool)), this, SLOT(uatPreferenceTriggered()));
        break;
    }
    case PREF_CUSTOM:
    case PREF_STATIC_TEXT:
    case PREF_OBSOLETE:
        break;
    default:
        // A type we currently don't handle (e.g. PREF_FILENAME). Just open
        // the prefs dialog.
        QString title = QString("%1" UTF8_HORIZONTAL_ELLIPSIS).arg(pref->title);
        QAction *mpa = addAction(title);
        connect(mpa, SIGNAL(triggered(bool)), this, SLOT(modulePreferencesTriggered()));
        break;
    }
}

void ProtocolPreferencesMenu::disableProtocolTriggered()
{
    EnabledProtocolsDialog enable_proto_dialog(this);
    enable_proto_dialog.selectProtocol(protocol_);
    hide();
    enable_proto_dialog.exec();
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

    bpa->setBoolValue();

    prefs_apply(module_);
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }

    wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void ProtocolPreferencesMenu::enumPreferenceTriggered()
{
    EnumPreferenceAction *epa = static_cast<EnumPreferenceAction *>(QObject::sender());
    if (!epa) return;

    if (epa->setEnumValue()) { // Changed
        prefs_apply(module_);
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
        }

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
