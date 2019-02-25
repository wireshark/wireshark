/********************************************************************************
** Form generated from reading UI file 'packet_comment_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PACKET_COMMENT_DIALOG_H
#define UI_PACKET_COMMENT_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_PacketCommentDialog
{
public:
    QVBoxLayout *verticalLayout;
    QPlainTextEdit *commentTextEdit;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *PacketCommentDialog)
    {
        if (PacketCommentDialog->objectName().isEmpty())
            PacketCommentDialog->setObjectName(QString::fromUtf8("PacketCommentDialog"));
        PacketCommentDialog->resize(400, 300);
        PacketCommentDialog->setModal(true);
        verticalLayout = new QVBoxLayout(PacketCommentDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        commentTextEdit = new QPlainTextEdit(PacketCommentDialog);
        commentTextEdit->setObjectName(QString::fromUtf8("commentTextEdit"));

        verticalLayout->addWidget(commentTextEdit);

        buttonBox = new QDialogButtonBox(PacketCommentDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(PacketCommentDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), PacketCommentDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), PacketCommentDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(PacketCommentDialog);
    } // setupUi

    void retranslateUi(QDialog *PacketCommentDialog)
    {
        Q_UNUSED(PacketCommentDialog);
    } // retranslateUi

};

namespace Ui {
    class PacketCommentDialog: public Ui_PacketCommentDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PACKET_COMMENT_DIALOG_H
