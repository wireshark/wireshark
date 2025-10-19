/* main_window.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ui/preference_utils.h"

#include "main_window.h"

#include "file.h"

#include "epan/dfilter/dfilter-translator.h"

#include <app/application_flavor.h>
#include <wsutil/filesystem.h>
#include <wsutil/version_info.h>

#include <ui/commandline.h>

#include <QClipboard>
#include <QTextCodec>

#include "funnel_statistics.h"
#include "main_application.h"
#include "packet_list.h"
#include "utils/profile_switcher.h"
#include "utils/qt_ui_utils.h"
#include "widgets/display_filter_combo.h"

// Packet Menu actions
static QList<QAction *> dynamic_packet_menu_actions;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_stack_(nullptr),
    welcome_page_(nullptr),
    cur_layout_(QVector<unsigned>()),
    packet_list_(nullptr),
    proto_tree_(nullptr),
    data_source_tab_(nullptr),
    packet_diagram_(nullptr),
    df_combo_box_(nullptr),
    main_status_bar_(nullptr),
    profile_switcher_(new ProfileSwitcher(this)),
    use_capturing_title_(false)
{
    findTextCodecs();
}

MainWindow::~MainWindow()
{
    clearAddedPacketMenus();
}

void MainWindow::findTextCodecs() {
    const QList<int> mibs = QTextCodec::availableMibs();
    QRegularExpression ibmRegExp("^IBM([0-9]+).*$");
    QRegularExpression iso8859RegExp("^ISO-8859-([0-9]+).*$");
    QRegularExpression windowsRegExp("^WINDOWS-([0-9]+).*$");
    QRegularExpressionMatch match;
    for (int mib : mibs) {
        QTextCodec *codec = QTextCodec::codecForMib(mib);
        // QTextCodec::availableMibs() returns a list of hard-coded MIB
        // numbers, it doesn't check if they are really available. ICU data may
        // not have been compiled with support for all encodings.
        if (!codec) {
            continue;
        }

        QString key = codec->name().toUpper();
        char rank;

        if (key.localeAwareCompare("IBM") < 0) {
            rank = 1;
        } else if ((match = ibmRegExp.match(key)).hasMatch()) {
            rank = match.captured(1).size(); // Up to 5
        } else if (key.localeAwareCompare("ISO-8859-") < 0) {
            rank = 6;
        } else if ((match = iso8859RegExp.match(key)).hasMatch()) {
            rank = 6 + match.captured(1).size(); // Up to 6 + 2
        } else if (key.localeAwareCompare("WINDOWS-") < 0) {
            rank = 9;
        } else if ((match = windowsRegExp.match(key)).hasMatch()) {
            rank = 9 + match.captured(1).size(); // Up to 9 + 4
        } else {
            rank = 14;
        }
        // This doesn't perfectly well order the IBM codecs because it's
        // annoying to properly place IBM00858 and IBM00924 in the middle of
        // code page numbers not zero padded to 5 digits.
        // We could manipulate the key further to have more commonly used
        // charsets earlier. IANA MIB ordering would be unexpected:
        // https://www.iana.org/assignments/character-sets/character-sets.xml
        // For data about use in HTTP (other protocols can be quite different):
        // https://w3techs.com/technologies/overview/character_encoding

        key.prepend(char('0' + rank));
        // We use a map here because, due to backwards compatibility,
        // the same QTextCodec may be returned for multiple MIBs, which
        // happens for GBK/GB2312, EUC-KR/windows-949/UHC, and others.
        text_codec_map_.insert(key, codec);
    }
}

bool MainWindow::hasSelection()
{
    if (packet_list_)
        return packet_list_->multiSelectActive();
    return false;
}

/*
 * As hasSelection() is not looking for one single packet
 * selection, but at least 2, this method returns true in
 * this specific case.
 */
bool MainWindow::hasUniqueSelection()
{
    if (packet_list_)
        return packet_list_->uniqueSelectActive();
    return false;
}

QList<int> MainWindow::selectedRows(bool useFrameNum)
{
    if (packet_list_)
        return packet_list_->selectedRows(useFrameNum);
    return QList<int>();
}

frame_data* MainWindow::frameDataForRow(int row) const
{
    if (packet_list_)
        return packet_list_->getFDataForRow(row);

    return Q_NULLPTR;
}

void MainWindow::insertColumn(QString name, QString abbrev, int pos)
{
    int colnr = 0;
    if (name.length() > 0 && abbrev.length() > 0)
    {
        colnr = column_prefs_add_custom(COL_CUSTOM, name.toStdString().c_str(), abbrev.toStdString().c_str(), pos);
        packet_list_->columnsChanged();
        packet_list_->resizeColumnToContents(colnr);
        prefs_main_write();
    }
}

void MainWindow::gotoFrame(int packet_num)
{
    if (packet_num > 0) {
        packet_list_->goToPacket(packet_num);
    }
}

QString MainWindow::getFilter()
{
    return df_combo_box_->currentText();
}

MainStatusBar *MainWindow::statusBar()
{
    return main_status_bar_;
}

void MainWindow::setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType)
{
    emit filterAction(filter, action, filterType);
}

/*
 * Used for registering custom packet menus
 *
 * @param funnel_action a custom packet menu action
 */
void MainWindow::appendPacketMenu(FunnelAction* funnel_action)
{
    dynamic_packet_menu_actions.append(funnel_action);
    connect(funnel_action, &FunnelAction::triggered, funnel_action, &FunnelAction::triggerPacketCallback);
}

/*
 * Returns the list of registered packet menu actions
 *
 * After ensuring that all stored custom packet menu actions
 * are registered with the Wireshark GUI, it returns them as a list
 * so that they can potentially be displayed to a user.
 *
 * @return the list of registered packet menu actions
 */
QList<QAction *> MainWindow::getPacketMenuActions()
{
    if (funnel_statistics_packet_menus_modified()) {
        // If the packet menus were modified, we need to clear the already
        // loaded packet menus to avoid duplicates
        this->clearAddedPacketMenus();
        funnel_statistics_load_packet_menus();
    }
    return dynamic_packet_menu_actions;
}

/*
 * Clears the list of registered packet menu actions
 *
 * Clears the list of registered packet menu actions
 * and frees all associated memory.
 */
void MainWindow::clearAddedPacketMenus()
{
    for( int i=0; i<dynamic_packet_menu_actions.count(); ++i )
    {
        delete dynamic_packet_menu_actions[i];
    }
    dynamic_packet_menu_actions.clear();
}


/*
 * Adds the custom packet menus to the supplied QMenu
 *
 * This method takes in QMenu and the selected packet's data
 * and adds all applicable custom packet menus to it.
 *
 * @param ctx_menu The menu to add the packet menu entries to
 * @param finfo_array The data in the selected packet
 * @return true if a packet menu was added to the ctx_menu
 */
bool MainWindow::addPacketMenus(QMenu * ctx_menu, GPtrArray *finfo_array)
{
    bool insertedPacketMenu = false;
    QList<QAction *> myPacketMenuActions = this->getPacketMenuActions();
    if (myPacketMenuActions.isEmpty()) {
        return insertedPacketMenu;
    }

    // Build a set of fields present for efficient lookups
    QSet<QString> fieldsPresent = QSet<QString>();
    for (unsigned fieldInfoIndex = 0; fieldInfoIndex < finfo_array->len; fieldInfoIndex++) {
        field_info *fi = (field_info *)g_ptr_array_index (finfo_array, fieldInfoIndex);
        fieldsPresent.insert(QString(fi->hfinfo->abbrev));
    }

    // Place actions in the relevant (sub)menu
    // The 'root' menu is the ctx_menu, so map NULL to that
    QHash<QString, QMenu *> menuTextToMenus;
    menuTextToMenus.insert(NULL, ctx_menu);
    foreach (QAction * action, myPacketMenuActions) {
        if (! qobject_cast<FunnelAction *>(action)) {
            continue;
        }
        FunnelAction * packetAction = qobject_cast<FunnelAction *>(action);

        // Only display a menu if all required fields are present
        if (!fieldsPresent.contains(packetAction->getPacketRequiredFields())) {
            continue;
        }

        packetAction->setPacketData(finfo_array);
        packetAction->addToMenu(ctx_menu, menuTextToMenus);
        insertedPacketMenu = true;
    }
    return insertedPacketMenu;
}

const char *MainWindow::translator_ = "translator";
const char *MainWindow::translated_filter_ = "translated filter";

void MainWindow::addDisplayFilterTranslationActions(QMenu *copy_menu) {
    if (!copy_menu) {
        return;
    }

    char **df_translators = get_dfilter_translator_list();

    if (df_translators == NULL || df_translators[0] == NULL) {
        g_free(df_translators);
        return;
    }

    copy_menu->addSeparator();

    for (size_t idx = 0; df_translators[idx]; idx++) {
        QString translator = df_translators[idx];
        QString action_text;
        if (idx == 0) {
            action_text = tr("Display filter as %1").arg(translator);
        } else {
            action_text = tr("…as %1").arg(translator);
        }
        QAction *xlate_action = copy_menu->addAction(action_text);
        xlate_action->setProperty(translator_, QVariant::fromValue(translator));
        xlate_action->setEnabled(false);
        connect(xlate_action, &QAction::triggered, this, &MainWindow::copyDisplayFilterTranslation);
        df_translate_actions_ += xlate_action;
    }

    g_free(df_translators);
}

void MainWindow::updateDisplayFilterTranslationActions(const QString &df_text)
{
    for (QAction *xlate_action : df_translate_actions_) {
        bool enable = false;
        QString translated_filter;
        if (!df_text.isEmpty()) {
            QString translator = xlate_action->property(translator_).toString();
            translated_filter = gchar_free_to_qstring((char *)translate_dfilter(qUtf8Printable(translator),
                                                                                 qUtf8Printable(df_text)));
            if (!translated_filter.isEmpty()) {
                enable = true;
            }
        }
        xlate_action->setEnabled(enable);
        xlate_action->setProperty(translated_filter_, QVariant::fromValue(translated_filter));
    }
}

void MainWindow::copyDisplayFilterTranslation()
{
    QAction *xlate_action = qobject_cast<QAction *>(sender());
    if (!xlate_action) {
        return;
    }

    QString translated_filter = xlate_action->property(translated_filter_).toString();
    mainApp->clipboard()->setText(translated_filter);
}

QString MainWindow::replaceWindowTitleVariables(QString title)
{
    title.replace("%P", get_profile_name());
    title.replace("%V", get_ws_vcs_version_info());

#ifdef HAVE_LIBPCAP
    char* capture_comment = commandline_get_first_capture_comment();
    if (capture_comment) {
        // Use the first capture comment from command line.
        title.replace("%C", capture_comment);
    } else {
        // No capture comment.
        title.remove("%C");
    }
#else
    title.remove("%C");
#endif

    if (title.contains("%F")) {
        // %F is file path of the capture file.
        if (capture_file_.capFile()) {
            // get_dirname() will overwrite the argument so make a copy first
            char *filename = g_strdup(capture_file_.capFile()->filename);
            QString file(get_dirname(filename));
            g_free(filename);
#ifndef _WIN32
            // Substitute HOME with ~
            QString homedir(g_getenv("HOME"));
            if (!homedir.isEmpty()) {
                homedir.remove(QRegularExpression("[/]+$"));
                file.replace(homedir, "~");
            }
#endif
            title.replace("%F", file);
        } else {
            // No file loaded, no folder name
            title.remove("%F");
        }
    }

    if (title.contains("%S")) {
        // %S is a conditional separator (" - ") that only shows when surrounded by variables
        // with values or static text. Remove repeating, leading and trailing separators.
        title.replace(QRegularExpression("(%S)+"), "%S");
        title.remove(QRegularExpression("^%S|%S$"));
#ifdef __APPLE__
        // On macOS we separate with a unicode em dash
        title.replace("%S", " " UTF8_EM_DASH " ");
#else
        title.replace("%S", " - ");
#endif
    }

    return title;
}

void MainWindow::setMainWindowTitle(QString title)
{
    if (title.isEmpty()) {
        if (application_flavor_is_wireshark()) {
            title = tr("The Wireshark Network Analyzer");
        } else {
            title = tr("The Stratoshark System Call and Log Analyzer");
        }
    }

    if (prefs.gui_prepend_window_title && prefs.gui_prepend_window_title[0]) {
        QString custom_title = replaceWindowTitleVariables(prefs.gui_prepend_window_title);
        if (custom_title.length() > 0) {
            title.prepend(QStringLiteral("[%1] ").arg(custom_title));
        }
    }

    if (prefs.gui_window_title && prefs.gui_window_title[0]) {
        QString custom_title = replaceWindowTitleVariables(prefs.gui_window_title);
        if (custom_title.length() > 0) {
#ifdef __APPLE__
            // On macOS we separate the titles with a unicode em dash
            title.append(QStringLiteral(" %1 %2").arg(UTF8_EM_DASH, custom_title));
#else
            title.append(QStringLiteral(" [%1]").arg(custom_title));
#endif
        }
    }

    setWindowTitle(title);
    setWindowFilePath(NULL);
}

void MainWindow::setTitlebarForCaptureInProgress()
{
    use_capturing_title_ = true;
    updateTitlebar();
}

void MainWindow::updateTitlebar()
{
    if (use_capturing_title_ && capture_file_.capFile()) {
        setMainWindowTitle(tr("Capturing from %1").arg(cf_get_tempfile_source(capture_file_.capFile())));
    } else if (capture_file_.capFile() && capture_file_.capFile()->filename) {
        setMainWindowTitle(QStringLiteral("[*]%1").arg(capture_file_.fileDisplayName()));
        //
        // XXX - on non-Mac platforms, put in the application
        // name?  Or do so only for temporary files?
        //
        if (!capture_file_.capFile()->is_tempfile) {
            //
            // Set the file path; that way, for macOS, it'll set the
            // "proxy icon".
            //
            setWindowFilePath(capture_file_.filePath());
        }
        setWindowModified(cf_has_unsaved_data(capture_file_.capFile()));
    } else {
        /* We have no capture file. */
        setMainWindowTitle();
    }
}

