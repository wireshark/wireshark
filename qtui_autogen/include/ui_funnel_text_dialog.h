/********************************************************************************
** Form generated from reading UI file 'funnel_text_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FUNNEL_TEXT_DIALOG_H
#define UI_FUNNEL_TEXT_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_FunnelTextDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTextEdit *textEdit;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *findLineEdit;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *FunnelTextDialog)
    {
        if (FunnelTextDialog->objectName().isEmpty())
            FunnelTextDialog->setObjectName(QString::fromUtf8("FunnelTextDialog"));
        FunnelTextDialog->resize(620, 450);
        verticalLayout = new QVBoxLayout(FunnelTextDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        textEdit = new QTextEdit(FunnelTextDialog);
        textEdit->setObjectName(QString::fromUtf8("textEdit"));

        verticalLayout->addWidget(textEdit);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(FunnelTextDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        findLineEdit = new QLineEdit(FunnelTextDialog);
        findLineEdit->setObjectName(QString::fromUtf8("findLineEdit"));

        horizontalLayout->addWidget(findLineEdit);


        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(FunnelTextDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(FunnelTextDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), FunnelTextDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), FunnelTextDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(FunnelTextDialog);
    } // setupUi

    void retranslateUi(QDialog *FunnelTextDialog)
    {
        FunnelTextDialog->setWindowTitle(QApplication::translate("FunnelTextDialog", "Dialog", nullptr));
#ifndef QT_NO_TOOLTIP
        label->setToolTip(QApplication::translate("FunnelTextDialog", "<html><head/><body><p>Enter some text or a regular expression. It will be highlighted above.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        label->setText(QApplication::translate("FunnelTextDialog", "Highlight:", nullptr));
#ifndef QT_NO_TOOLTIP
        findLineEdit->setToolTip(QApplication::translate("FunnelTextDialog", "<html><head/><body><p>Enter some text or a regular expression. It will be highlighted above.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
    } // retranslateUi

};

namespace Ui {
    class FunnelTextDialog: public Ui_FunnelTextDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_FUNNEL_TEXT_DIALOG_H
