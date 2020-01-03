/* preferences_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "preferences_dialog.h"
#include <ui_preferences_dialog.h>

#include "module_preferences_scroll_area.h"

#include <epan/prefs-int.h>
#include <epan/decode_as.h>
#include <ui/language.h>
#include <ui/preference_utils.h>
#include <ui/simple_dialog.h>
#include <ui/recent.h>
#include <main_window.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include "wireshark_application.h"

extern "C" {
// Callbacks prefs routines

static guint
module_prefs_unstash(module_t *module, gpointer data)
{
    gboolean *must_redissect_p = static_cast<gboolean *>(data);
    pref_unstash_data_t unstashed_data;

    unstashed_data.handle_decode_as = TRUE;

    module->prefs_changed_flags = 0;        /* assume none of them changed */
    for (GList *pref_l = module->prefs; pref_l && pref_l->data; pref_l = gxx_list_next(pref_l)) {
        pref_t *pref = gxx_list_data(pref_t *, pref_l);

        if (prefs_get_type(pref) == PREF_OBSOLETE || prefs_get_type(pref) == PREF_STATIC_TEXT) continue;

        unstashed_data.module = module;
        pref_unstash(pref, &unstashed_data);
    }

    /* If any of them changed, indicate that we must redissect and refilter
       the current capture (if we have one), as the preference change
       could cause packets to be dissected differently. */
    *must_redissect_p |= module->prefs_changed_flags;

    if (prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, module_prefs_unstash, data);

    return 0;     /* Keep unstashing. */
}

static guint
module_prefs_clean_stash(module_t *module, gpointer)
{
    for (GList *pref_l = module->prefs; pref_l && pref_l->data; pref_l = gxx_list_next(pref_l)) {
        pref_t *pref = gxx_list_data(pref_t *, pref_l);

        if (prefs_get_type(pref) == PREF_OBSOLETE || prefs_get_type(pref) == PREF_STATIC_TEXT) continue;

        pref_clean_stash(pref, Q_NULLPTR);
    }

    if (prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, module_prefs_clean_stash, Q_NULLPTR);

    return 0;     /* Keep cleaning modules */
}

} // extern "C"

// Preference tree items
const int APPEARANCE_ITEM = 0;

//placeholder key to keep dynamically loaded preferences
static const char* MODULES_NAME = "Modules";

PreferencesDialog::PreferencesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    pd_ui_(new Ui::PreferencesDialog),
    model_(this),
    advancedPrefsModel_(this),
    advancedPrefsDelegate_(this),
    modulePrefsModel_(this)
{
    advancedPrefsModel_.setSourceModel(&model_);
    modulePrefsModel_.setSourceModel(&model_);
    saved_capture_no_extcap_ = prefs.capture_no_extcap;

    // Some classes depend on pref_ptr_to_pref_ so this MUST be called after
    // model_.populate().
    pd_ui_->setupUi(this);
    loadGeometry();

    setWindowTitle(wsApp->windowTitleString(tr("Preferences")));

    pd_ui_->advancedView->setModel(&advancedPrefsModel_);
    pd_ui_->advancedView->setItemDelegate(&advancedPrefsDelegate_);
    advancedPrefsModel_.setFirstColumnSpanned(pd_ui_->advancedView);

    pd_ui_->prefsView->setModel(&modulePrefsModel_);

    pd_ui_->splitter->setStretchFactor(0, 1);
    pd_ui_->splitter->setStretchFactor(1, 5);
    pd_ui_->prefsView->sortByColumn(ModulePrefsModel::colName, Qt::AscendingOrder);

    //Set the Appearance leaf to expanded
    pd_ui_->prefsView->setExpanded(modulePrefsModel_.index(APPEARANCE_ITEM, 0), true);


    // PreferencesPane, prefsView, and stackedWidget must all correspond to each other.
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Appearance)] = pd_ui_->appearanceFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Layout)] = pd_ui_->layoutFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Columns)] = pd_ui_->columnFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::FontAndColors)] = pd_ui_->fontandcolorFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Capture)] = pd_ui_->captureFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Expert)] = pd_ui_->expertFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::FilterButtons)] = pd_ui_->filterExpressonsFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::RSAKeys)] = pd_ui_->rsaKeysFrame;
    prefs_pane_to_item_[PrefsModel::typeToString(PrefsModel::Advanced)] = pd_ui_->advancedFrame;
    prefs_pane_to_item_[MODULES_NAME] = NULL;

    pd_ui_->filterExpressonsFrame->setUat(uat_get_table_by_name("Display expressions"));
    pd_ui_->expertFrame->setUat(uat_get_table_by_name("Expert Info Severity Level Configuration"));

    connect(pd_ui_->prefsView, SIGNAL(goToPane(QString)), this, SLOT(selectPane(QString)));
}

PreferencesDialog::~PreferencesDialog()
{
    delete pd_ui_;
    prefs_modules_foreach_submodules(NULL, module_prefs_clean_stash, NULL);
}

void PreferencesDialog::setPane(const QString module_name)
{
    pd_ui_->prefsView->setPane(module_name);
}

void PreferencesDialog::showEvent(QShowEvent *)
{
    QStyleOption style_opt;
    int new_prefs_tree_width =  pd_ui_->prefsView->style()->subElementRect(QStyle::SE_TreeViewDisclosureItem, &style_opt).left();
    QList<int> sizes = pd_ui_->splitter->sizes();

#ifdef Q_OS_WIN
    new_prefs_tree_width *= 2;
#endif
    pd_ui_->prefsView->resizeColumnToContents(ModulePrefsModel::colName);
    new_prefs_tree_width += pd_ui_->prefsView->columnWidth(ModulePrefsModel::colName);
    pd_ui_->prefsView->setMinimumWidth(new_prefs_tree_width);

    sizes[1] += sizes[0] - new_prefs_tree_width;
    sizes[0] = new_prefs_tree_width;
    pd_ui_->splitter->setSizes(sizes);
    pd_ui_->splitter->setStretchFactor(0, 1);

    pd_ui_->advancedView->expandAll();
    pd_ui_->advancedView->setSortingEnabled(true);
    pd_ui_->advancedView->sortByColumn(AdvancedPrefsModel::colName, Qt::AscendingOrder);

    int one_em = fontMetrics().height();
    pd_ui_->advancedView->setColumnWidth(AdvancedPrefsModel::colName, one_em * 12); // Don't let long items widen things too much
    pd_ui_->advancedView->resizeColumnToContents(AdvancedPrefsModel::colStatus);
    pd_ui_->advancedView->resizeColumnToContents(AdvancedPrefsModel::colType);
    pd_ui_->advancedView->setColumnWidth(AdvancedPrefsModel::colValue, one_em * 30);
}

void PreferencesDialog::selectPane(QString pane)
{
    if (prefs_pane_to_item_.contains(pane)) {
        pd_ui_->stackedWidget->setCurrentWidget(prefs_pane_to_item_[pane]);
    } else {
        //If not found in prefs_pane_to_item_, it must be an individual module
        module_t* module = prefs_find_module(pane.toStdString().c_str());
        if (module != NULL) {
            QWidget* moduleWindow = prefs_pane_to_item_[MODULES_NAME];
            if (moduleWindow != NULL) {
                pd_ui_->stackedWidget->removeWidget(moduleWindow);
                delete moduleWindow;
            }

            moduleWindow = new ModulePreferencesScrollArea(module);
            prefs_pane_to_item_[MODULES_NAME] = moduleWindow;
            pd_ui_->stackedWidget->addWidget(moduleWindow);
            pd_ui_->stackedWidget->setCurrentWidget(moduleWindow);
        }
    }
}

void PreferencesDialog::on_advancedSearchLineEdit_textEdited(const QString &search_re)
{
    advancedPrefsModel_.setFilter(search_re);
    /* If items are filtered out, then filtered back in, the tree remains colapsed
       Force an expansion */
    pd_ui_->advancedView->expandAll();
}

void PreferencesDialog::on_buttonBox_accepted()
{
    gchar* err = NULL;
    unsigned int redissect_flags = 0;

    // XXX - We should validate preferences as the user changes them, not here.
    // XXX - We're also too enthusiastic about setting must_redissect.
    prefs_modules_foreach_submodules(NULL, module_prefs_unstash, (gpointer)&redissect_flags);

    if (redissect_flags & PREF_EFFECT_GUI_LAYOUT) {
        // Layout type changed, reset sizes
        recent.gui_geometry_main_upper_pane = 0;
        recent.gui_geometry_main_lower_pane = 0;
    }

    pd_ui_->columnFrame->unstash();
    pd_ui_->filterExpressonsFrame->acceptChanges();
    pd_ui_->expertFrame->acceptChanges();
#ifdef HAVE_LIBGNUTLS
    pd_ui_->rsaKeysFrame->acceptChanges();
#endif

    //Filter expressions don't affect dissection, so there is no need to
    //send any events to that effect.  However, the app needs to know
    //about any button changes.
    wsApp->emitAppSignal(WiresharkApplication::FilterExpressionsChanged);

    prefs_main_write();
    if (save_decode_as_entries(&err) < 0)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
        g_free(err);
    }

    write_language_prefs();
    wsApp->loadLanguage(QString(language));

#ifdef HAVE_AIRPCAP
  /*
   * Load the Wireshark decryption keys (just set) and save
   * the changes to the adapters' registry
   */
  //airpcap_load_decryption_keys(airpcap_if_list);
#endif

    // gtk/prefs_dlg.c:prefs_main_apply_all
    /*
     * Apply the protocol preferences first - "gui_prefs_apply()" could
     * cause redissection, and we have to make sure the protocol
     * preference changes have been fully applied.
     */
    prefs_apply_all();

    /* Fill in capture options with values from the preferences */
    prefs_to_capture_opts();

#ifdef HAVE_AIRPCAP
//    prefs_airpcap_update();
#endif

    wsApp->setMonospaceFont(prefs.gui_qt_font_name);

    if (redissect_flags & PREF_EFFECT_FIELDS) {
        wsApp->queueAppSignal(WiresharkApplication::FieldsChanged);
    }

    if (redissect_flags & PREF_EFFECT_DISSECTION) {
        /* Redissect all the packets, and re-evaluate the display filter. */
        wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
    }
    wsApp->queueAppSignal(WiresharkApplication::PreferencesChanged);

    if (redissect_flags & PREF_EFFECT_GUI_LAYOUT) {
        wsApp->queueAppSignal(WiresharkApplication::RecentPreferencesRead);
    }

    if (prefs.capture_no_extcap != saved_capture_no_extcap_)
        wsApp->refreshLocalInterfaces();
}

void PreferencesDialog::on_buttonBox_rejected()
{
    //handle frames that don't have their own OK/Cancel "buttons"
    pd_ui_->filterExpressonsFrame->rejectChanges();
    pd_ui_->expertFrame->rejectChanges();
#ifdef HAVE_LIBGNUTLS
    pd_ui_->rsaKeysFrame->rejectChanges();
#endif
}

void PreferencesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_PREFERENCES_DIALOG);
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
