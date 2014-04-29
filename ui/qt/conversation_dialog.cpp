/* conversation_dialog.cpp
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

#include "conversation_dialog.h"
#include "ui_conversation_dialog.h"

#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/stat_cmd_args.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/recent.h"
#include "ui/tap-tcp-stream.h"

#include "wireshark_application.h"

#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QList>
#include <QMap>
#include <QMessageBox>
#include <QTabWidget>
#include <QToolButton>

#include <QDebug>

// To do:
// - https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6727
//   - Wide last column?
//   + No arrows on unsorted columns
//   - Add follow stream to context menu
//   + Change "A <- B" to "B -> A"
// - Improper wildcard handling https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8010
// - TShark consolidation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6310
// - Display filter entry?
// - Add follow, copy & graph actions to context menu.

// Bugs:
// - Name resolution doesn't do anything if its preference is disabled.
// - Columns don't resize correctly.

// Fixed bugs:
// - Friendly unit displays https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9231
// - Misleading bps calculation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8703

Q_DECLARE_METATYPE(conversation_type_e)

QMap<QString, conversation_type_e> conv_proto_to_type_;

ConversationDialog::ConversationDialog(QWidget *parent, capture_file *cf, const char *stat_arg) :
    QDialog(parent),
    ui(new Ui::ConversationDialog),
    cap_file_(cf)
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    // XXX Use recent settings instead
    if (parent) {
        resize(parent->width(), parent->height() * 3 / 4);
    }

    QMenu *copy_menu = new QMenu();
    QAction *ca;
    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in CSV (Comma Separated Values) format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsCsv()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the YAML data serialization format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsYaml()));
    copy_bt_->setMenu(copy_menu);

    follow_bt_ = ui->buttonBox->addButton(tr("Follow Stream..."), QDialogButtonBox::ActionRole);
    follow_bt_->setToolTip(tr("Follow a TCP or UDP stream."));
    connect(follow_bt_, SIGNAL(clicked()), this, SLOT(followStream()));

    graph_bt_ = ui->buttonBox->addButton(tr("Graph..."), QDialogButtonBox::ActionRole);
    graph_bt_->setToolTip(tr("Graph a TCP conversation."));
    connect(graph_bt_, SIGNAL(clicked()), this, SLOT(graphTcp()));

    QList<conversation_type_e> conv_types;
    for (GList *conv_tab = recent.conversation_tabs; conv_tab; conv_tab = conv_tab->next) {
        conversation_type_e ct = conversation_title_to_type((const char *)conv_tab->data);
        if (!conv_types.contains(ct)) {
            conv_types.append(ct);
        }
    }

    // Reasonable defaults?
    if (conv_types.isEmpty()) {
        conv_types << CONV_TYPE_ETHERNET << CONV_TYPE_IPV4 << CONV_TYPE_IPV6 <<CONV_TYPE_TCP << CONV_TYPE_UDP;
    }

    // Bring the command-line specified type to the front.
    initStatCmdMap();
    QStringList stat_args = QString(stat_arg).split(",");
    if (stat_args.length() > 1 && conv_proto_to_type_.contains(stat_args[1])) {
        conversation_type_e ct = conv_proto_to_type_[stat_args[1]];
        conv_types.removeAll(ct);
        conv_types.prepend(ct);
        if (stat_args.length() > 2) {
            filter_ = stat_args[2];
        }
    }

    foreach (conversation_type_e conv_type, conv_types) {
        addConversationType(conv_type);
    }

    for (int i = CONV_TYPE_ETHERNET; i < N_CONV_TYPES; i++) {
        conversation_type_e ct = (conversation_type_e) i;
        QString title = conversation_title(ct);

        QAction *conv_action = new QAction(title, this);
        conv_action->setData(qVariantFromValue(ct));
        conv_action->setCheckable(true);
        conv_action->setChecked(conv_types.contains(ct));
        connect(conv_action, SIGNAL(triggered()), this, SLOT(toggleConversation()));
        conv_type_menu_.addAction(conv_action);
    }

    ui->conversationTypePushButton->setMenu(&conv_type_menu_);

    updateWidgets();
    itemSelectionChanged();

    ui->nameResolutionCheckBox->setChecked(gbl_resolv_flags.network_name);

    ui->conversationTabWidget->currentWidget()->setFocus();

    connect(ui->conversationTabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(itemSelectionChanged()));

    if (cap_file_) {
        cf_retap_packets(cap_file_);
    }
}

ConversationDialog::~ConversationDialog()
{
    prefs_clear_string_list(recent.conversation_tabs);
    recent.conversation_tabs = NULL;

    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    foreach (QAction *ca, conv_type_menu_.actions()) {
        conversation_type_e conv_type = ca->data().value<conversation_type_e>();
        if (conv_type_to_tree_.contains(conv_type) && ca->isChecked()) {
            char *title = g_strdup(conversation_title(conv_type));
            if (conv_type_to_tree_[conv_type] == cur_tree) {
                recent.conversation_tabs = g_list_prepend(recent.conversation_tabs, title);
            } else {
                recent.conversation_tabs = g_list_append(recent.conversation_tabs, title);
            }
        }
    }
    delete ui;
}

void ConversationDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
        ui->displayFilterCheckBox->setEnabled(false);
    }
}

void ConversationDialog::initStatCmdMap()
{
    if (conv_proto_to_type_.size() > 0) {
        return;
    }

    conv_proto_to_type_["eth"] = CONV_TYPE_ETHERNET;
    conv_proto_to_type_["fc"] = CONV_TYPE_FIBRE_CHANNEL;
    conv_proto_to_type_["fddi"] = CONV_TYPE_FDDI;
    conv_proto_to_type_["ip"] = CONV_TYPE_IPV4;
    conv_proto_to_type_["ipv6"] = CONV_TYPE_IPV6;
    conv_proto_to_type_["ipx"] = CONV_TYPE_IPX;
    conv_proto_to_type_["jxta"] = CONV_TYPE_JXTA;
    conv_proto_to_type_["ncp"] = CONV_TYPE_NCP;
    conv_proto_to_type_["rsvp"] = CONV_TYPE_RSVP;
    conv_proto_to_type_["sctp"] = CONV_TYPE_SCTP;
    conv_proto_to_type_["tcp"] = CONV_TYPE_TCP;
    conv_proto_to_type_["tr"] = CONV_TYPE_TOKEN_RING;
    conv_proto_to_type_["udp"] = CONV_TYPE_UDP;
    conv_proto_to_type_["usb"] = CONV_TYPE_USB;
    conv_proto_to_type_["wlan"] = CONV_TYPE_WLAN;
}

bool ConversationDialog::addConversationType(conversation_type_e conv_type)
{
    if (conv_type_to_tree_.contains(conv_type)) {
        return false;
    }

    ConversationTreeWidget *conv_tree = new ConversationTreeWidget(this, conv_type);

    conv_type_to_tree_[conv_type] = conv_tree;

    ui->conversationTabWidget->addTab(conv_tree, conversation_title(conv_type));
    connect(conv_tree, SIGNAL(itemSelectionChanged()),
            this, SLOT(itemSelectionChanged()));
    connect(conv_tree, SIGNAL(titleChanged(QWidget*,QString)),
            this, SLOT(setTabText(QWidget*,QString)));
    connect(conv_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
            this, SLOT(chainFilterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
    connect(ui->nameResolutionCheckBox, SIGNAL(toggled(bool)),
            conv_tree, SLOT(setNameResolutionEnabled(bool)));

    // XXX Move to ConversationTreeWidget ctor?
    const char *filter = NULL;
    if (ui->displayFilterCheckBox->isChecked()) {
        filter = cap_file_->dfilter;
    } else if (!filter_.isEmpty()) {
        filter = filter_.toUtf8().constData();
    }
    GString *error_string = register_tap_listener(conversation_tap_name(conv_type), conv_tree, filter, 0,
                                                  ConversationTreeWidget::tapReset,
                                                  ConversationTreeWidget::tapPacket,
                                                  ConversationTreeWidget::tapDraw);

    if (error_string) {
        QMessageBox::warning(this, tr("Conversation %1 failed to register tap listener").arg(conversation_title(conv_type)),
                             error_string->str);
        g_string_free(error_string, TRUE);
    }
    return true;
}

conversation_type_e ConversationDialog::tabType(int index)
{
    ConversationTreeWidget *conv_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->widget(index));
    if (!conv_tree) {
        return N_CONV_TYPES; // Need a "none" type?
    }
    return conv_tree->conversationType();
}

conv_item_t *ConversationDialog::currentConversation()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());

    if (!cur_tree || cur_tree->selectedItems().count() < 1) {
        return NULL;
    }

    return cur_tree->selectedItems()[0]->data(0, Qt::UserRole).value<conv_item_t *>();
}

void ConversationDialog::followStream()
{
    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    QString filter;
    follow_type_t ftype = FOLLOW_TCP;
    switch (conv_item->ptype) {
    case PT_TCP:
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
        break;
    case PT_UDP:
        filter = QString("udp.stream eq %1").arg(conv_item->conv_id);
        ftype = FOLLOW_UDP;
        break;
    default:
        break;
    }

    if (filter.length() < 1) {
        return;
    }

    chainFilterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    openFollowStreamDialog(ftype);
}

void ConversationDialog::copyAsCsv()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        QStringList rdsl;
        foreach (QVariant v, cur_tree->rowData(row)) {
            if (!v.isValid()) {
                rdsl << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << endl;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ConversationDialog::copyAsYaml()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << endl;
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        stream << "-" << endl;
        foreach (QVariant v, cur_tree->rowData(row)) {
            stream << " - " << v.toString() << endl;
        }
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ConversationDialog::graphTcp()
{
    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    // XXX The GTK+ code opens the TCP Stream dialog. We might want
    // to open the IO Graph dialog instead.
    QString filter;
    if (conv_item->ptype == PT_TCP) {
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
    } else {
        return;
    }

    chainFilterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    openTcpStreamGraph(GRAPH_TSEQ_TCPTRACE);
}

void ConversationDialog::updateWidgets()
{
    QWidget *cur_w = ui->conversationTabWidget->currentWidget();
    ui->conversationTabWidget->setUpdatesEnabled(false);
    ui->conversationTabWidget->clear();
    foreach (QAction *ca, conv_type_menu_.actions()) {
        conversation_type_e conv_type = ca->data().value<conversation_type_e>();
        if (conv_type_to_tree_.contains(conv_type) && ca->isChecked()) {
            ui->conversationTabWidget->addTab(conv_type_to_tree_[conv_type],
                                              conv_type_to_tree_[conv_type]->conversationTitle());
            conv_type_to_tree_[conv_type]->setNameResolutionEnabled(ui->nameResolutionCheckBox->isChecked());
        }
    }
    ui->conversationTabWidget->setCurrentWidget(cur_w);
    ui->conversationTabWidget->setUpdatesEnabled(true);
}

void ConversationDialog::toggleConversation()
{
    QAction *ca = qobject_cast<QAction *>(QObject::sender());
    if (!ca) {
        return;
    }

    conversation_type_e conv_type = ca->data().value<conversation_type_e>();
    bool new_conv = addConversationType(conv_type);
    updateWidgets();

    if (ca->isChecked()) {
        ui->conversationTabWidget->setCurrentWidget(conv_type_to_tree_[conv_type]);
    }

    if (new_conv) {
        if (cap_file_) {
            cf_retap_packets(cap_file_);
        }
    }
}

void ConversationDialog::itemSelectionChanged()
{
    bool copy_enable = ui->conversationTabWidget->currentWidget() ? true : false;
    bool follow_enable = false, graph_enable = false;
    conv_item_t *conv_item = currentConversation();

    if (cap_file_ && conv_item) {
        switch (conv_item->ptype) {
        case PT_TCP:
            graph_enable = true;
            // Fall through
        case PT_UDP:
            follow_enable = true;
            break;
        default:
            break;
        }
    }

    copy_bt_->setEnabled(copy_enable);
    follow_bt_->setEnabled(follow_enable);
    graph_bt_->setEnabled(graph_enable);
}

void ConversationDialog::on_nameResolutionCheckBox_toggled(bool checked)
{
    Q_UNUSED(checked);
    updateWidgets();
}

void ConversationDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (!cap_file_) {
        return;
    }

    const char *filter = NULL;
    if (checked) {
        filter = cap_file_->dfilter;
    } else if (!filter_.isEmpty()) {
        filter = filter_.toUtf8().constData();
    }

    for (int i = 0; i < ui->conversationTabWidget->count(); i++) {
        set_tap_dfilter(ui->conversationTabWidget->widget(i), filter);
    }

    cf_retap_packets(cap_file_);
}

void ConversationDialog::setTabText(QWidget *tree, const QString &text)
{
    // Could use QObject::sender as well
    int index = ui->conversationTabWidget->indexOf(tree);
    if (index >= 0) {
        ui->conversationTabWidget->setTabText(index, text);
    }
}

void ConversationDialog::chainFilterAction(QString &filter, FilterAction::Action action, FilterAction::ActionType type)
{
    if (cap_file_) { // We probably shouldn't fail silently
        emit filterAction(filter, action, type);
    }
}

void ConversationDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_CONVERSATIONS_DIALOG);
}

// Stat command + args

static void
conversation_init(const char *stat_arg, void* userdata _U_) {
    Q_UNUSED(stat_arg)
    wsApp->emitStatCommandSignal("Conversation", stat_arg, NULL);
}

extern "C" {
void
register_tap_listener_all_conversations(void)
{
    register_stat_cmd_arg("conv,eth", conversation_init, NULL);
    register_stat_cmd_arg("conv,fc", conversation_init, NULL);
    register_stat_cmd_arg("conv,fddi", conversation_init, NULL);
    register_stat_cmd_arg("conv,ip", conversation_init, NULL);
    register_stat_cmd_arg("conv,ipv6", conversation_init, NULL);
    register_stat_cmd_arg("conv,ipx", conversation_init, NULL);
    register_stat_cmd_arg("conv,jxta", conversation_init, NULL);
    register_stat_cmd_arg("conv,ncp", conversation_init, NULL);
    register_stat_cmd_arg("conv,rsvp", conversation_init, NULL);
    register_stat_cmd_arg("conv,sctp", conversation_init, NULL);
    register_stat_cmd_arg("conv,tcp", conversation_init, NULL);
    register_stat_cmd_arg("conv,tr", conversation_init, NULL);
    register_stat_cmd_arg("conv,udp", conversation_init, NULL);
    register_stat_cmd_arg("conv,usb", conversation_init, NULL);
    register_stat_cmd_arg("conv,wlan", conversation_init, NULL);
}
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
