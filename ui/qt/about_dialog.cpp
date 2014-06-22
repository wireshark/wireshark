/* about_dialog.cpp
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

#include "about_dialog.h"
#include "ui_about_dialog.h"

#include "wireshark_application.h"
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
#include "../register.h"

#include "ui/text_import_scanner.h"
#include "ui/last_open_dir.h"
#include "ui/alert_box.h"
#include "ui/help_url.h"

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"
#include "wsutil/plugins.h"
#include "wsutil/copyright_info.h"
#include "wsutil/ws_version_info.h"

#include "qt_ui_utils.h"

#include <QFontMetrics>
#include <QTextStream>
#include <QUrl>

#include "wireshark_application.h"

// To do:
// - Tweak and enhance ui...

const QString AboutDialog::about_folders_row(const char *name, const QString dir, const char *typ_file)
{
    int one_em = fontMetrics().height();

    QString short_dir = fontMetrics().elidedText(dir, Qt::ElideMiddle, one_em * 18); // Arbitrary

    // It would be really nice to be able to add a tooltip with the
    // full path here but Qt's rich text doesn't appear to support
    // "a title=".
    return QString("<tr><td>%1</td><td><a href=\"%2\">%3</a></td><td>%4</td></tr>\n")
            .arg(name)
            .arg(QUrl::fromLocalFile(dir).toString())
            .arg(short_dir)
            .arg(typ_file);
}

static void plugins_add_description(const char *name, const char *version,
                                    const char *types, const char *filename,
                                    void *user_data )
{
    QList<QStringList> *plugin_data = (QList<QStringList> *)user_data;
    QStringList plugin_row = QStringList() << name << version << types << filename;
    *plugin_data << plugin_row;
}


const QString AboutDialog::plugins_scan()
{
    QList<QStringList> plugin_data;
    QString plugin_table;

#ifdef HAVE_PLUGINS
    plugins_get_descriptions(plugins_add_description, &plugin_data);
#endif

#ifdef HAVE_LUA
    wslua_plugins_get_descriptions(plugins_add_description, &plugin_data);
#endif

    int one_em = fontMetrics().height();
    QString short_file;

    foreach (QStringList plugin_row, plugin_data) {
        short_file = fontMetrics().elidedText(plugin_row[3], Qt::ElideMiddle, one_em * 22); // Arbitrary
        plugin_table += QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td></tr>\n")
                .arg(plugin_row[0]) // Name
                .arg(plugin_row[1]) // Version
                .arg(plugin_row[2]) // Type
                .arg(short_file);
    }
    return plugin_table;
}

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    QFile f_authors;
    QFile f_license;
    const char *constpath;
    QString message;
#if defined (HAVE_LIBSMI) || defined (HAVE_GEOIP)
    char *path = NULL;
    gint i;
    gchar **resultArray;
#endif


    /* Wireshark tab */

    /* Construct the message string */
    message = QString(
        "Version %1\n"
        "\n"
        "%2"
        "\n"
        "%3"
        "\n"
        "%4"
        "\n"
        "Wireshark is Open Source Software released under the GNU General Public License.\n"
        "\n"
        "Check the man page and http://www.wireshark.org for more information.")
        .arg(get_ws_vcs_version_info()).arg(get_copyright_info()).arg(comp_info_str->str)
        .arg(runtime_info_str->str);

    ui->label_wireshark->setTextInteractionFlags(Qt::TextSelectableByMouse);
    ui->label_wireshark->setText(message);

/* Check if it is a dev release... (VERSION_MINOR is odd in dev release) */
#if VERSION_MINOR & 1
        ui->label_logo->setPixmap( QPixmap( ":/about/wssplash_dev.png" ) );
#endif


    /* Authors */

    f_authors.setFileName(get_datafile_path("AUTHORS-SHORT"));
    f_authors.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_authors(&f_authors);
    ReadFile_authors.setCodec("UTF-8");

    ui->pte_Authors->setFont(wsApp->monospaceFont());
    ui->pte_Authors->insertPlainText(ReadFile_authors.readAll());
    ui->pte_Authors->moveCursor(QTextCursor::Start);

    /* Folders */

    int one_em = fontMetrics().height();

    // Couldn't get CSS to work.
    message = QString("<table cellpadding=\"%1\">\n").arg(one_em / 4);
    message += "<tr><th align=\"left\">Name</th><th align=\"left\">Location</th><th align=\"left\">Typical Files</th></tr>\n";

    /* "file open" */
    message += about_folders_row("\"File\" dialogs", get_last_open_dir(), "capture files");

    /* temp */
    message += about_folders_row("Temp", g_get_tmp_dir(), "untitled capture files");

    /* pers conf */
    message += about_folders_row("Personal configuration",
                                 gchar_free_to_qstring(get_persconffile_path("", FALSE)),
                                 "<i>dfilters</i>, <i>preferences</i>, <i>ethers</i>, ...");

    /* global conf */
    constpath = get_datafile_dir();
    if (constpath != NULL) {
        message += about_folders_row("Global configuration", constpath,
                                     "<i>dfilters</i>, <i>preferences</i>, <i>manuf</i>, ...");
    }

    /* system */
    message += about_folders_row("System", get_systemfile_dir(), "<i>ethers</i>, <i>ipxnets</i>");

    /* program */
    message += about_folders_row("Program", get_progfile_dir(), "program files");

#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
    /* pers plugins */
    message += about_folders_row("Personal Plugins", gchar_free_to_qstring(get_plugins_pers_dir()),
                      "dissector plugins");

    /* global plugins */
    message += about_folders_row("Global Plugins", get_plugin_dir(), "dissector plugins");
#endif

#ifdef HAVE_GEOIP
    /* GeoIP */
    path = geoip_db_get_paths();

    resultArray = g_strsplit(path, G_SEARCHPATH_SEPARATOR_S, 10);

    for(i = 0; resultArray[i]; i++) {
        message += about_folders_row("GeoIP path", g_strstrip(resultArray[i]),
                                     "GeoIP database search path");
    }
    g_strfreev(resultArray);
    g_free(path);
#endif

#ifdef HAVE_LIBSMI
    /* SMI MIBs/PIBs */
    path = oid_get_default_mib_path();

    resultArray = g_strsplit(path, G_SEARCHPATH_SEPARATOR_S, 10);

    for(i = 0; resultArray[i]; i++) {
        message += about_folders_row("MIB/PIB path", g_strstrip(resultArray[i]),
                                     "SMI MIB/PIB search path");
    }
    g_strfreev(resultArray);
    g_free(path);
#endif

    message += "</table>";
    ui->label_folders->setText(message);


    /* Plugins */

    message = QString("<table cellpadding=\"%1\">\n").arg(one_em / 4);
    message += "<tr><th align=\"left\">Name</th><th align=\"left\">Version</th><th align=\"left\">Type</th><th align=\"left\">Path</th></tr>\n";

    message += plugins_scan();

    message += "</table>";
    ui->label_plugins->setText(message);

    /* License */

#if defined(_WIN32)
    f_license.setFileName(get_datafile_path("COPYING.txt"));
#else
    f_license.setFileName(get_datafile_path("COPYING"));
#endif

    f_license.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_license(&f_license);

    ui->pte_License->setFont(wsApp->monospaceFont());
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
