/* about_dialog.cpp
 *
 * $Id$
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

#include "about_dialog.h"
#include "ui_about_dialog.h"

#include "wireshark_application.h"
#include "main.cpp"
#include <wsutil/filesystem.h>

#ifdef HAVE_LIBSMI
#include <epan/oids.h>
#endif
#ifdef HAVE_GEOIP
#include <epan/geoip_db.h>
#endif
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif

#include "../log.h"
#include "../version_info.h"
#include "../register.h"

#include "ui/text_import_scanner.h"
#include "ui/last_open_dir.h"
#include "ui/alert_box.h"
#include "ui/help_url.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"
#include "wsutil/plugins.h"

#include <QtGui>
#include <QTextStream>

// To do:
// - Found better solution to reuse comp_info_str and runtime_info_str (Remove ugly hack...)
// - Tweat and enhance ui...

void AboutDialog::about_folders_row(const char *name, const char *dir, const char *typ_file)
{
    ui->tbFolders->setRowCount(ui->tbFolders->rowCount() + 1);

    ui->tbFolders->setItem(ui->tbFolders->rowCount()-1, 0, new QTableWidgetItem(name));
    ui->tbFolders->setItem(ui->tbFolders->rowCount()-1, 1, new QTableWidgetItem(dir));
    ui->tbFolders->setItem(ui->tbFolders->rowCount()-1, 2, new QTableWidgetItem(typ_file));

}

void plugins_add_description(const char *name, const char *version,
                        const char *types, const char *filename,
                        void *user_data _U_ )
{

    QTableWidget *tbPlugins = (QTableWidget *)user_data;
    tbPlugins->setRowCount(tbPlugins->rowCount() + 1);

    tbPlugins->setItem(tbPlugins->rowCount()-1, 0, new QTableWidgetItem(name));
    tbPlugins->setItem(tbPlugins->rowCount()-1, 1, new QTableWidgetItem(version));
    tbPlugins->setItem(tbPlugins->rowCount()-1, 2, new QTableWidgetItem(types));
    tbPlugins->setItem(tbPlugins->rowCount()-1, 3, new QTableWidgetItem(filename));
}


void AboutDialog::plugins_scan()
{
#ifdef HAVE_PLUGINS
    plugins_get_descriptions(plugins_add_description, ui->tbPlugins);
#endif

#ifdef HAVE_LUA
    wslua_plugins_get_descriptions(plugins_add_description, ui->tbPlugins);
#endif
}

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    QFile f_authors;
    QFile f_license;
    char *path = NULL;
    const char *constpath;
    gchar       *message;
    const char *version;
#if defined (HAVE_LIBSMI) || defined (HAVE_GEOIP)
    gint i;
    gchar **resultArray;
#endif


    /* Wireshark tab */

    /* Assemble the compile-time version information string */
    comp_info_str = g_string_new("Compiled ");

    // Ugly hack... copy from ui/qt/main.cpp */
    get_compiled_version_info(comp_info_str, get_qt_compiled_info, get_gui_compiled_info);

    /* Assemble the run-time version information string */
    runtime_info_str = g_string_new("Running ");

    get_runtime_version_info(runtime_info_str, get_gui_runtime_info);

    /* Construct the message string */
    message = g_strdup_printf(
        "Version " VERSION "%s\n"
        "\n"
        "%s"
        "\n"
        "%s"
        "\n"
        "%s"
        "\n"
        "Wireshark is Open Source Software released under the GNU General Public License.\n"
        "\n"
        "Check the man page and http://www.wireshark.org for more information.",
        wireshark_svnversion, get_copyright_info(), comp_info_str->str,
        runtime_info_str->str);

    ui->label_wireshark->setTextInteractionFlags(Qt::TextSelectableByMouse);
    ui->label_wireshark->setText(message);

    /* VERSION_MINOR is const char * with CMake and int with Autofoo.... */
    version = (const char *)VERSION_MINOR;

    /* Check if Dev release... (VERSION_MINOR is odd) */
    if ( atoi(version) % 2 == 1)
    {
        ui->label_logo->setPixmap( QPixmap( ":/about/wssplash_dev.png" ) );
    }


    /* Authors */
    f_authors.setFileName(get_datafile_path("AUTHORS-SHORT"));
    f_authors.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_authors(&f_authors);

    ui->pte_Authors->insertPlainText(ReadFile_authors.readAll());
    ui->pte_Authors->moveCursor(QTextCursor::Start);

    /* Folders */

    /* set column widths */

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tbFolders->horizontalHeader()->setResizeMode(2, QHeaderView::Stretch);
#else
    ui->tbFolders->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
#endif

    ui->tbFolders->setRowCount(0);

    /* "file open" */
    about_folders_row("\"File\" dialogs", get_last_open_dir(), "capture files");

    /* temp */
    about_folders_row("Temp", g_get_tmp_dir(), "untitled capture files");

    /* pers conf */
    path = get_persconffile_path("", FALSE);
    about_folders_row("Personal configuration", path, "\"dfilters\", \"preferences\", \"ethers\", ...");
    g_free(path);

    /* global conf */
    constpath = get_datafile_dir();
    if (constpath != NULL) {
        about_folders_row("Global configuration", constpath, "\"dfilters\", \"preferences\", \"manuf\", ...");
    }

    /* system */
    constpath = get_systemfile_dir();
    about_folders_row("System", constpath, "\"ethers\", \"ipxnets\"");

    /* program */
    constpath = get_progfile_dir();
    about_folders_row("Program", constpath, "program files");

#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
    /* pers plugins */
    path = get_plugins_pers_dir();
    about_folders_row("Personal Plugins", path, "dissector plugins");
    g_free(path);

    /* global plugins */
    about_folders_row("Global Plugins", get_plugin_dir(), "dissector plugins");
#endif

#ifdef HAVE_PYTHON
    /* global python bindings */
    about_folders_row("Python Bindings", get_wspython_dir(), "python bindings");
#endif

#ifdef HAVE_GEOIP
    /* GeoIP */
    path = geoip_db_get_paths();

    resultArray = g_strsplit(path, G_SEARCHPATH_SEPARATOR_S, 10);

    for(i = 0; resultArray[i]; i++)
        about_folders_row("GeoIP path", g_strstrip(resultArray[i]), "GeoIP database search path");
    g_strfreev(resultArray);
    g_free(path);
#endif

#ifdef HAVE_LIBSMI
    /* SMI MIBs/PIBs */
    path = oid_get_default_mib_path();

    resultArray = g_strsplit(path, G_SEARCHPATH_SEPARATOR_S, 10);

    for(i = 0; resultArray[i]; i++)
        about_folders_row("MIB/PIB path", g_strstrip(resultArray[i]), "SMI MIB/PIB search path");
    g_strfreev(resultArray);
    g_free(path);
#endif


    /* Plugins */
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tbPlugins->horizontalHeader()->setResizeMode(3, QHeaderView::Stretch);
#else
    ui->tbPlugins->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
#endif
    plugins_scan();

    /* License */

    #if defined(_WIN32)
        f_license.setFileName(get_datafile_path("COPYING.txt"));
    #else
        f_license.setFileName(get_datafile_path("COPYING"));
    #endif

    f_license.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_license(&f_license);

    ui->pte_License->insertPlainText(ReadFile_license.readAll());
    ui->pte_License->moveCursor(QTextCursor::Start);
}

AboutDialog::~AboutDialog()
{
    delete ui;
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
