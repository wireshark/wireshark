/********************************************************************************
** Form generated from reading UI file 'enabled_protocols_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ENABLED_PROTOCOLS_DIALOG_H
#define UI_ENABLED_PROTOCOLS_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_EnabledProtocolsDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTreeView *protocol_tree_;
    QLabel *disable_notice_text_;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *search_line_edit_;
    QSpacerItem *horizontalSpacer;
    QPushButton *enable_all_button_;
    QPushButton *disable_all_button_;
    QPushButton *invert_button_;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *EnabledProtocolsDialog)
    {
        if (EnabledProtocolsDialog->objectName().isEmpty())
            EnabledProtocolsDialog->setObjectName(QString::fromUtf8("EnabledProtocolsDialog"));
        EnabledProtocolsDialog->resize(987, 595);
        verticalLayout = new QVBoxLayout(EnabledProtocolsDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        protocol_tree_ = new QTreeView(EnabledProtocolsDialog);
        protocol_tree_->setObjectName(QString::fromUtf8("protocol_tree_"));
        protocol_tree_->setSortingEnabled(true);

        verticalLayout->addWidget(protocol_tree_);

        disable_notice_text_ = new QLabel(EnabledProtocolsDialog);
        disable_notice_text_->setObjectName(QString::fromUtf8("disable_notice_text_"));
        disable_notice_text_->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);

        verticalLayout->addWidget(disable_notice_text_);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(EnabledProtocolsDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        search_line_edit_ = new QLineEdit(EnabledProtocolsDialog);
        search_line_edit_->setObjectName(QString::fromUtf8("search_line_edit_"));

        horizontalLayout->addWidget(search_line_edit_);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        enable_all_button_ = new QPushButton(EnabledProtocolsDialog);
        enable_all_button_->setObjectName(QString::fromUtf8("enable_all_button_"));

        horizontalLayout->addWidget(enable_all_button_);

        disable_all_button_ = new QPushButton(EnabledProtocolsDialog);
        disable_all_button_->setObjectName(QString::fromUtf8("disable_all_button_"));

        horizontalLayout->addWidget(disable_all_button_);

        invert_button_ = new QPushButton(EnabledProtocolsDialog);
        invert_button_->setObjectName(QString::fromUtf8("invert_button_"));

        horizontalLayout->addWidget(invert_button_);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(EnabledProtocolsDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(EnabledProtocolsDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), EnabledProtocolsDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), EnabledProtocolsDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(EnabledProtocolsDialog);
    } // setupUi

    void retranslateUi(QDialog *EnabledProtocolsDialog)
    {
        EnabledProtocolsDialog->setWindowTitle(QApplication::translate("EnabledProtocolsDialog", "Dialog", nullptr));
        disable_notice_text_->setText(QApplication::translate("EnabledProtocolsDialog", "<small><i>Disabling a protocol prevents higher layer protocols from being displayed</i></small>", nullptr));
        label->setText(QApplication::translate("EnabledProtocolsDialog", "Search:", nullptr));
        enable_all_button_->setText(QApplication::translate("EnabledProtocolsDialog", "Enable All", nullptr));
        disable_all_button_->setText(QApplication::translate("EnabledProtocolsDialog", "Disable All", nullptr));
        invert_button_->setText(QApplication::translate("EnabledProtocolsDialog", "Invert", nullptr));
    } // retranslateUi

};

namespace Ui {
    class EnabledProtocolsDialog: public Ui_EnabledProtocolsDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ENABLED_PROTOCOLS_DIALOG_H
