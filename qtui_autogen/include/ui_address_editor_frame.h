/********************************************************************************
** Form generated from reading UI file 'address_editor_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ADDRESS_EDITOR_FRAME_H
#define UI_ADDRESS_EDITOR_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include "accordion_frame.h"
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_AddressEditorFrame
{
public:
    QHBoxLayout *horizontalLayout;
    QToolButton *nameResolutionPreferencesToolButton;
    QSpacerItem *horizontalSpacer_2;
    QLabel *addressLabel;
    QComboBox *addressComboBox;
    QSpacerItem *horizontalSpacer_3;
    QLabel *label;
    SyntaxLineEdit *nameLineEdit;
    QSpacerItem *horizontalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(AccordionFrame *AddressEditorFrame)
    {
        if (AddressEditorFrame->objectName().isEmpty())
            AddressEditorFrame->setObjectName(QString::fromUtf8("AddressEditorFrame"));
        AddressEditorFrame->resize(833, 34);
        AddressEditorFrame->setFrameShape(QFrame::NoFrame);
        AddressEditorFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout = new QHBoxLayout(AddressEditorFrame);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        nameResolutionPreferencesToolButton = new QToolButton(AddressEditorFrame);
        nameResolutionPreferencesToolButton->setObjectName(QString::fromUtf8("nameResolutionPreferencesToolButton"));

        horizontalLayout->addWidget(nameResolutionPreferencesToolButton);

        horizontalSpacer_2 = new QSpacerItem(81, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        addressLabel = new QLabel(AddressEditorFrame);
        addressLabel->setObjectName(QString::fromUtf8("addressLabel"));

        horizontalLayout->addWidget(addressLabel);

        addressComboBox = new QComboBox(AddressEditorFrame);
        addressComboBox->setObjectName(QString::fromUtf8("addressComboBox"));

        horizontalLayout->addWidget(addressComboBox);

        horizontalSpacer_3 = new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        label = new QLabel(AddressEditorFrame);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        nameLineEdit = new SyntaxLineEdit(AddressEditorFrame);
        nameLineEdit->setObjectName(QString::fromUtf8("nameLineEdit"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(nameLineEdit->sizePolicy().hasHeightForWidth());
        nameLineEdit->setSizePolicy(sizePolicy);
        nameLineEdit->setMinimumSize(QSize(80, 0));

        horizontalLayout->addWidget(nameLineEdit);

        horizontalSpacer = new QSpacerItem(20, 13, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        buttonBox = new QDialogButtonBox(AddressEditorFrame);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setMaximumSize(QSize(16777215, 27));
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout->addWidget(buttonBox);

        horizontalLayout->setStretch(1, 3);
        horizontalLayout->setStretch(6, 1);

        retranslateUi(AddressEditorFrame);

        QMetaObject::connectSlotsByName(AddressEditorFrame);
    } // setupUi

    void retranslateUi(AccordionFrame *AddressEditorFrame)
    {
        AddressEditorFrame->setWindowTitle(QApplication::translate("AddressEditorFrame", "Frame", nullptr));
        nameResolutionPreferencesToolButton->setText(QApplication::translate("AddressEditorFrame", "Name Resolution Preferences\342\200\246", nullptr));
        addressLabel->setText(QApplication::translate("AddressEditorFrame", "Address:", nullptr));
        label->setText(QApplication::translate("AddressEditorFrame", "Name:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class AddressEditorFrame: public Ui_AddressEditorFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ADDRESS_EDITOR_FRAME_H
