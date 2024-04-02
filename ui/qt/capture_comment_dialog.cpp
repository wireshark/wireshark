/* packet_comment_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "capture_comment_dialog.h"
#include <ui_capture_comment_dialog.h>

#include "file.h"

#include "ui/simple_dialog.h"
#include "ui/qt/utils/qt_ui_utils.h"
#include "main_application.h"

#include <QTabBar>
#include <QPushButton>
#include <QPlainTextEdit>

class CaptureCommentTabWidget : public QTabWidget
{
    Q_OBJECT
public:
    CaptureCommentTabWidget(QWidget *parent = nullptr) : QTabWidget(parent)
    {

        setTabsClosable(true);
        setMovable(true);
        connect(this, &QTabWidget::tabCloseRequested, this, &CaptureCommentTabWidget::closeTab);
        connect(tabBar(), &QTabBar::tabMoved, this, &CaptureCommentTabWidget::setTabTitles);
    }
    int addTab(QWidget *page);
    void tabRemoved(int index) override;
    void closeTab(int index);
    void setReadOnly(bool ro);
    char** getCommentsText();

private:
    void setTabTitles(int from, int to);
};

int CaptureCommentTabWidget::addTab(QWidget *page)
{
    return QTabWidget::addTab(page, tr("Comment %1").arg(count() + 1));
}

void CaptureCommentTabWidget::closeTab(int index)
{
    QPlainTextEdit *te;
    te = qobject_cast<QPlainTextEdit*>(widget(index));
    if (te != nullptr) {
        removeTab(index);
        delete te;
    }
}

void CaptureCommentTabWidget::setReadOnly(bool ro)
{
    QPlainTextEdit *commentTextEdit;
    for (int index = 0; index < count(); index++) {
        commentTextEdit = qobject_cast<QPlainTextEdit*>(widget(index));
        if (commentTextEdit != nullptr) {
            commentTextEdit->setReadOnly(ro);
        }
    }
}

void CaptureCommentTabWidget::tabRemoved(int index)
{
    setTabTitles(index, count() - 1);
}

char** CaptureCommentTabWidget::getCommentsText()
{
    /* glib 2.68 and later have g_strv_builder which is slightly
     * more convenient.
     */
    QPlainTextEdit *te;
    GPtrArray *ptr_array = g_ptr_array_new_full(count() + 1, g_free);
    for (int index = 0; index < count(); index++) {
        te = qobject_cast<QPlainTextEdit*>(widget(index));
        if (te != nullptr) {
            char *str = qstring_strdup(te->toPlainText());

            /*
             * Make sure this would fit in a pcapng option.
             *
             * XXX - 65535 is the maximum size for an option in pcapng;
             * what if another capture file format supports larger
             * comments?
             */
            if (strlen(str) > 65535) {
                /* It doesn't fit.  Give up. */
                g_ptr_array_free(ptr_array, true);
                return nullptr;
            }
            g_ptr_array_add(ptr_array, str);
        }
    }
    g_ptr_array_add(ptr_array, nullptr);
    return (char**)g_ptr_array_free(ptr_array, false);
}

void CaptureCommentTabWidget::setTabTitles(int from, int to)
{
    if (from < to) {
        for (; from <= to; from++) {
            this->setTabText(from, tr("Comment %1").arg(from + 1));
        }
    } else {
        for (; from >= to; from--) {
            this->setTabText(from, tr("Comment %1").arg(from + 1));
        }
    }
}

CaptureCommentDialog::CaptureCommentDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::CaptureCommentDialog)
{

    ui->setupUi(this);
    loadGeometry();
    setWindowSubtitle(tr("Edit Capture Comments"));

    ui->sectionTabWidget->setTabBarAutoHide(true);
    this->actionAddButton = ui->buttonBox->addButton(tr("Add Comment"), QDialogButtonBox::ActionRole);
    connect(this->actionAddButton, &QPushButton::clicked, this, &CaptureCommentDialog::addComment);

    connect(this, SIGNAL(captureCommentChanged()),
        mainApp->mainWindow(), SLOT(updateForUnsavedChanges()));
    QTimer::singleShot(0, this, SLOT(updateWidgets()));
}

CaptureCommentDialog::~CaptureCommentDialog()
{
    delete ui;
}

void CaptureCommentDialog::addComment()
{
    QPlainTextEdit *commentTextEdit;
    CaptureCommentTabWidget *currentTW = qobject_cast<CaptureCommentTabWidget*>(ui->sectionTabWidget->currentWidget());
    if (currentTW != nullptr) {
        commentTextEdit = new QPlainTextEdit(currentTW);

        currentTW->addTab(commentTextEdit);
    }
}

void CaptureCommentDialog::updateWidgets()
{
    QPlainTextEdit *commentTextEdit;
    CaptureCommentTabWidget *shbTW;
    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);

    if (file_closed_ || !cap_file_.isValid()) {
        for (int shb = 0; shb < ui->sectionTabWidget->count(); shb++) {
            shbTW = qobject_cast<CaptureCommentTabWidget*>(ui->sectionTabWidget->widget(shb));
            shbTW->setReadOnly(true);
        }
        if (save_bt) {
            save_bt->setEnabled(false);
        }
        actionAddButton->setEnabled(false);
        WiresharkDialog::updateWidgets();
        return;
    }

    bool enable = wtap_dump_can_write(cap_file_.capFile()->linktypes, WTAP_COMMENT_PER_SECTION);
    save_bt->setEnabled(enable);
    actionAddButton->setEnabled(enable);

    unsigned num_shbs = wtap_file_get_num_shbs(cap_file_.capFile()->provider.wth);
    for (unsigned shb_idx = 0; shb_idx < num_shbs; shb_idx++) {
        shbTW = qobject_cast<CaptureCommentTabWidget*>(ui->sectionTabWidget->widget(shb_idx));
        if (shbTW == nullptr) {
            shbTW = new CaptureCommentTabWidget(ui->sectionTabWidget);
            ui->sectionTabWidget->addTab(shbTW, tr("Section %1").arg(shb_idx + 1));
        }
        wtap_block_t shb = wtap_file_get_shb(cap_file_.capFile()->provider.wth, shb_idx);
        unsigned num_comments = wtap_block_count_option(shb, OPT_COMMENT);
        char *shb_comment;
        for (unsigned index = 0; index < num_comments; index++) {
            commentTextEdit = qobject_cast<QPlainTextEdit*>(shbTW->widget(index));
            if (commentTextEdit == nullptr) {
                commentTextEdit = new QPlainTextEdit(shbTW);
                shbTW->addTab(commentTextEdit);
            }
            if (wtap_block_get_nth_string_option_value(shb, OPT_COMMENT, index,
                                                       &shb_comment) == WTAP_OPTTYPE_SUCCESS) {
                commentTextEdit->setPlainText(shb_comment);
            } else {
                // XXX: Should we warn about this failure?
                commentTextEdit->setPlainText("");
            }
            commentTextEdit->setReadOnly(!enable);
        }
        for (unsigned index = shbTW->count(); index > num_comments; index--) {
            shbTW->closeTab(index - 1);
        }
    }

    WiresharkDialog::updateWidgets();
}

void CaptureCommentDialog::on_buttonBox_helpRequested()
{
//    mainApp->helpTopicAction(HELP_CAPTURE_COMMENT_DIALOG);
}

void CaptureCommentDialog::on_buttonBox_accepted()
{
    int ret = QDialog::Rejected;

    if (file_closed_ || !cap_file_.capFile()->filename) {
        done(ret);
        return;
    }

    if (wtap_dump_can_write(cap_file_.capFile()->linktypes, WTAP_COMMENT_PER_SECTION))
    {
        CaptureCommentTabWidget *current;
        char** comments_text;
        for (int shb_idx = 0; shb_idx < ui->sectionTabWidget->count(); shb_idx++) {
            current = qobject_cast<CaptureCommentTabWidget*>(ui->sectionTabWidget->widget(shb_idx));
            comments_text = current->getCommentsText();
            if (comments_text == nullptr) {
                /* This is the only error we track currently, so it must be
                 * this. Tell the user and give up. */
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                              "A comment is too large to save in a capture file.");
                done(ret);
                return;
            }
            cf_update_section_comments(cap_file_.capFile(), shb_idx, comments_text);
            emit captureCommentChanged();
            ret = QDialog::Accepted;
        }
    }
    done(ret);
}

void CaptureCommentDialog::on_buttonBox_rejected()
{
    reject();
}

#include "capture_comment_dialog.moc"
