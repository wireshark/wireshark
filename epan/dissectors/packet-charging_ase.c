/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-charging_ase.c                                                      */
/* ../../tools/asn2wrs.py -b -e -p charging_ase -c ./charging_ase.cnf -s ./packet-charging_ase-template -D . Tariffing-Data-Types.asn */

/* Input file: packet-charging_ase-template.c */

#line 1 "../../asn1/charging_ase/packet-charging_ase-template.c"
/* packet-charging_ase-template.c
 * Copyright 2009 , Anders Broman <anders.broman [AT] ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * References: ETSI ES 201 296 V1.3.1 (2003-04)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-charging_ase.h"

#define PNAME  "Charging ASE"
#define PSNAME "ChargingASE"
#define PFNAME "chargingase"

/* Define the Charging ASE proto */
static int proto_charging_ase = -1;


/*--- Included file: packet-charging_ase-hf.c ---*/
#line 1 "../../asn1/charging_ase/packet-charging_ase-hf.c"
static int hf_charging_ase_charging_ase_ChargingMessageType_PDU = -1;  /* ChargingMessageType */
static int hf_charging_ase_crgt = -1;             /* ChargingTariffInformation */
static int hf_charging_ase_aocrg = -1;            /* AddOnChargingInformation */
static int hf_charging_ase_crga = -1;             /* ChargingAcknowledgementInformation */
static int hf_charging_ase_start = -1;            /* StartCharging */
static int hf_charging_ase_stop = -1;             /* StopCharging */
static int hf_charging_ase_acknowledgementIndicators = -1;  /* T_acknowledgementIndicators */
static int hf_charging_ase_extensions = -1;       /* SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField */
static int hf_charging_ase_extensions_item = -1;  /* ExtensionField */
static int hf_charging_ase_originationIdentification = -1;  /* ChargingReferenceIdentification */
static int hf_charging_ase_destinationIdentification = -1;  /* ChargingReferenceIdentification */
static int hf_charging_ase_chargingControlIndicators = -1;  /* ChargingControlIndicators */
static int hf_charging_ase_addOncharge = -1;      /* T_addOncharge */
static int hf_charging_ase_addOnChargeCurrency = -1;  /* CurrencyFactorScale */
static int hf_charging_ase_addOnChargePulse = -1;  /* PulseUnits */
static int hf_charging_ase_currency = -1;         /* Currency */
static int hf_charging_ase_chargingTariff = -1;   /* T_chargingTariff */
static int hf_charging_ase_tariffCurrency = -1;   /* TariffCurrency */
static int hf_charging_ase_tariffPulse = -1;      /* TariffPulse */
static int hf_charging_ase_local = -1;            /* INTEGER */
static int hf_charging_ase_global = -1;           /* OBJECT_IDENTIFIER */
static int hf_charging_ase_currencyFactorScale = -1;  /* CurrencyFactorScale */
static int hf_charging_ase_tariffDuration = -1;   /* TariffDuration */
static int hf_charging_ase_subTariffControl = -1;  /* SubTariffControl */
static int hf_charging_ase_pulseUnits = -1;       /* PulseUnits */
static int hf_charging_ase_chargeUnitTimeInterval = -1;  /* ChargeUnitTimeInterval */
static int hf_charging_ase_currencyFactor = -1;   /* CurrencyFactor */
static int hf_charging_ase_currencyScale = -1;    /* CurrencyScale */
static int hf_charging_ase_type = -1;             /* Code */
static int hf_charging_ase_criticality = -1;      /* CriticalityType */
static int hf_charging_ase_value = -1;            /* T_value */
static int hf_charging_ase_networkOperators = -1;  /* SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification */
static int hf_charging_ase_networkOperators_item = -1;  /* NetworkIdentification */
static int hf_charging_ase_stopIndicators = -1;   /* T_stopIndicators */
static int hf_charging_ase_currentTariffCurrency = -1;  /* TariffCurrencyFormat */
static int hf_charging_ase_tariffSwitchCurrency = -1;  /* TariffSwitchCurrency */
static int hf_charging_ase_nextTariffCurrency = -1;  /* TariffCurrencyFormat */
static int hf_charging_ase_tariffSwitchoverTime = -1;  /* TariffSwitchoverTime */
static int hf_charging_ase_communicationChargeSequenceCurrency = -1;  /* SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency */
static int hf_charging_ase_communicationChargeSequenceCurrency_item = -1;  /* CommunicationChargeCurrency */
static int hf_charging_ase_tariffControlIndicators = -1;  /* T_tariffControlIndicators */
static int hf_charging_ase_callAttemptChargeCurrency = -1;  /* CurrencyFactorScale */
static int hf_charging_ase_callSetupChargeCurrency = -1;  /* CurrencyFactorScale */
static int hf_charging_ase_currentTariffPulse = -1;  /* TariffPulseFormat */
static int hf_charging_ase_tariffSwitchPulse = -1;  /* TariffSwitchPulse */
static int hf_charging_ase_nextTariffPulse = -1;  /* TariffPulseFormat */
static int hf_charging_ase_communicationChargeSequencePulse = -1;  /* SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse */
static int hf_charging_ase_communicationChargeSequencePulse_item = -1;  /* CommunicationChargePulse */
static int hf_charging_ase_tariffControlIndicators_01 = -1;  /* T_tariffControlIndicators_01 */
static int hf_charging_ase_callAttemptChargePulse = -1;  /* PulseUnits */
static int hf_charging_ase_callSetupChargePulse = -1;  /* PulseUnits */
static int hf_charging_ase_networkIdentification = -1;  /* NetworkIdentification */
static int hf_charging_ase_referenceID = -1;      /* ReferenceID */
/* named bits */
static int hf_charging_ase_T_acknowledgementIndicators_accepted = -1;
static int hf_charging_ase_ChargingControlIndicators_subscriberCharge = -1;
static int hf_charging_ase_ChargingControlIndicators_immediateChangeOfActuallyAppliedTariff = -1;
static int hf_charging_ase_ChargingControlIndicators_delayUntilStart = -1;
static int hf_charging_ase_T_stopIndicators_callAttemptChargesApplicable = -1;
static int hf_charging_ase_SubTariffControl_oneTimeCharge = -1;
static int hf_charging_ase_T_tariffControlIndicators_non_cyclicTariff = -1;
static int hf_charging_ase_T_tariffControlIndicators_01_non_cyclicTariff = -1;

/*--- End of included file: packet-charging_ase-hf.c ---*/
#line 45 "../../asn1/charging_ase/packet-charging_ase-template.c"

static int ett_charging_ase = -1;

/*--- Included file: packet-charging_ase-ett.c ---*/
#line 1 "../../asn1/charging_ase/packet-charging_ase-ett.c"
static gint ett_charging_ase_ChargingMessageType = -1;
static gint ett_charging_ase_ChargingAcknowledgementInformation = -1;
static gint ett_charging_ase_T_acknowledgementIndicators = -1;
static gint ett_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField = -1;
static gint ett_charging_ase_ChargingControlIndicators = -1;
static gint ett_charging_ase_AddOnChargingInformation = -1;
static gint ett_charging_ase_T_addOncharge = -1;
static gint ett_charging_ase_ChargingTariffInformation = -1;
static gint ett_charging_ase_T_chargingTariff = -1;
static gint ett_charging_ase_Code = -1;
static gint ett_charging_ase_CommunicationChargeCurrency = -1;
static gint ett_charging_ase_CommunicationChargePulse = -1;
static gint ett_charging_ase_CurrencyFactorScale = -1;
static gint ett_charging_ase_ExtensionField = -1;
static gint ett_charging_ase_StartCharging = -1;
static gint ett_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification = -1;
static gint ett_charging_ase_StopCharging = -1;
static gint ett_charging_ase_T_stopIndicators = -1;
static gint ett_charging_ase_SubTariffControl = -1;
static gint ett_charging_ase_TariffCurrency = -1;
static gint ett_charging_ase_TariffSwitchCurrency = -1;
static gint ett_charging_ase_TariffCurrencyFormat = -1;
static gint ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency = -1;
static gint ett_charging_ase_T_tariffControlIndicators = -1;
static gint ett_charging_ase_TariffPulse = -1;
static gint ett_charging_ase_TariffSwitchPulse = -1;
static gint ett_charging_ase_TariffPulseFormat = -1;
static gint ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse = -1;
static gint ett_charging_ase_T_tariffControlIndicators_01 = -1;
static gint ett_charging_ase_ChargingReferenceIdentification = -1;

/*--- End of included file: packet-charging_ase-ett.c ---*/
#line 48 "../../asn1/charging_ase/packet-charging_ase-template.c"

static dissector_handle_t charging_ase_handle;


/*--- Included file: packet-charging_ase-fn.c ---*/
#line 1 "../../asn1/charging_ase/packet-charging_ase-fn.c"

static const asn_namedbit ChargingControlIndicators_bits[] = {
  {  0, &hf_charging_ase_ChargingControlIndicators_subscriberCharge, -1, -1, "subscriberCharge", NULL },
  {  1, &hf_charging_ase_ChargingControlIndicators_immediateChangeOfActuallyAppliedTariff, -1, -1, "immediateChangeOfActuallyAppliedTariff", NULL },
  {  2, &hf_charging_ase_ChargingControlIndicators_delayUntilStart, -1, -1, "delayUntilStart", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_ChargingControlIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ChargingControlIndicators_bits, hf_index, ett_charging_ase_ChargingControlIndicators,
                                    NULL);

  return offset;
}



static int
dissect_charging_ase_CurrencyFactor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_charging_ase_CurrencyScale(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CurrencyFactorScale_sequence[] = {
  { &hf_charging_ase_currencyFactor, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyFactor },
  { &hf_charging_ase_currencyScale, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyScale },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_CurrencyFactorScale(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CurrencyFactorScale_sequence, hf_index, ett_charging_ase_CurrencyFactorScale);

  return offset;
}



static int
dissect_charging_ase_TariffDuration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const asn_namedbit SubTariffControl_bits[] = {
  {  0, &hf_charging_ase_SubTariffControl_oneTimeCharge, -1, -1, "oneTimeCharge", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_SubTariffControl(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    SubTariffControl_bits, hf_index, ett_charging_ase_SubTariffControl,
                                    NULL);

  return offset;
}


static const ber_sequence_t CommunicationChargeCurrency_sequence[] = {
  { &hf_charging_ase_currencyFactorScale, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyFactorScale },
  { &hf_charging_ase_tariffDuration, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffDuration },
  { &hf_charging_ase_subTariffControl, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_charging_ase_SubTariffControl },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_CommunicationChargeCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommunicationChargeCurrency_sequence, hf_index, ett_charging_ase_CommunicationChargeCurrency);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency_sequence_of[1] = {
  { &hf_charging_ase_communicationChargeSequenceCurrency_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_charging_ase_CommunicationChargeCurrency },
};

static int
dissect_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency_sequence_of, hf_index, ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency);

  return offset;
}


static const asn_namedbit T_tariffControlIndicators_bits[] = {
  {  0, &hf_charging_ase_T_tariffControlIndicators_non_cyclicTariff, -1, -1, "non-cyclicTariff", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_T_tariffControlIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_tariffControlIndicators_bits, hf_index, ett_charging_ase_T_tariffControlIndicators,
                                    NULL);

  return offset;
}


static const ber_sequence_t TariffCurrencyFormat_sequence[] = {
  { &hf_charging_ase_communicationChargeSequenceCurrency, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency },
  { &hf_charging_ase_tariffControlIndicators, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_tariffControlIndicators },
  { &hf_charging_ase_callAttemptChargeCurrency, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyFactorScale },
  { &hf_charging_ase_callSetupChargeCurrency, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyFactorScale },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffCurrencyFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffCurrencyFormat_sequence, hf_index, ett_charging_ase_TariffCurrencyFormat);

  return offset;
}



static int
dissect_charging_ase_TariffSwitchoverTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TariffSwitchCurrency_sequence[] = {
  { &hf_charging_ase_nextTariffCurrency, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffCurrencyFormat },
  { &hf_charging_ase_tariffSwitchoverTime, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffSwitchoverTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffSwitchCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffSwitchCurrency_sequence, hf_index, ett_charging_ase_TariffSwitchCurrency);

  return offset;
}


static const ber_sequence_t TariffCurrency_sequence[] = {
  { &hf_charging_ase_currentTariffCurrency, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffCurrencyFormat },
  { &hf_charging_ase_tariffSwitchCurrency, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffSwitchCurrency },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffCurrency_sequence, hf_index, ett_charging_ase_TariffCurrency);

  return offset;
}



static int
dissect_charging_ase_PulseUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_charging_ase_ChargeUnitTimeInterval(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CommunicationChargePulse_sequence[] = {
  { &hf_charging_ase_pulseUnits, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_PulseUnits },
  { &hf_charging_ase_chargeUnitTimeInterval, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargeUnitTimeInterval },
  { &hf_charging_ase_tariffDuration, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffDuration },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_CommunicationChargePulse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommunicationChargePulse_sequence, hf_index, ett_charging_ase_CommunicationChargePulse);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse_sequence_of[1] = {
  { &hf_charging_ase_communicationChargeSequencePulse_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_charging_ase_CommunicationChargePulse },
};

static int
dissect_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse_sequence_of, hf_index, ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse);

  return offset;
}


static const asn_namedbit T_tariffControlIndicators_01_bits[] = {
  {  0, &hf_charging_ase_T_tariffControlIndicators_01_non_cyclicTariff, -1, -1, "non-cyclicTariff", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_T_tariffControlIndicators_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_tariffControlIndicators_01_bits, hf_index, ett_charging_ase_T_tariffControlIndicators_01,
                                    NULL);

  return offset;
}


static const ber_sequence_t TariffPulseFormat_sequence[] = {
  { &hf_charging_ase_communicationChargeSequencePulse, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse },
  { &hf_charging_ase_tariffControlIndicators_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_tariffControlIndicators_01 },
  { &hf_charging_ase_callAttemptChargePulse, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_PulseUnits },
  { &hf_charging_ase_callSetupChargePulse, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_PulseUnits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffPulseFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffPulseFormat_sequence, hf_index, ett_charging_ase_TariffPulseFormat);

  return offset;
}


static const ber_sequence_t TariffSwitchPulse_sequence[] = {
  { &hf_charging_ase_nextTariffPulse, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffPulseFormat },
  { &hf_charging_ase_tariffSwitchoverTime, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffSwitchoverTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffSwitchPulse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffSwitchPulse_sequence, hf_index, ett_charging_ase_TariffSwitchPulse);

  return offset;
}


static const ber_sequence_t TariffPulse_sequence[] = {
  { &hf_charging_ase_currentTariffPulse, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffPulseFormat },
  { &hf_charging_ase_tariffSwitchPulse, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffSwitchPulse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_TariffPulse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TariffPulse_sequence, hf_index, ett_charging_ase_TariffPulse);

  return offset;
}


static const value_string charging_ase_T_chargingTariff_vals[] = {
  {   0, "tariffCurrency" },
  {   1, "tariffPulse" },
  { 0, NULL }
};

static const ber_choice_t T_chargingTariff_choice[] = {
  {   0, &hf_charging_ase_tariffCurrency, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffCurrency },
  {   1, &hf_charging_ase_tariffPulse, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_TariffPulse },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_T_chargingTariff(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_chargingTariff_choice, hf_index, ett_charging_ase_T_chargingTariff,
                                 NULL);

  return offset;
}



static int
dissect_charging_ase_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_charging_ase_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string charging_ase_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_charging_ase_local  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_charging_ase_INTEGER },
  {   1, &hf_charging_ase_global , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_charging_ase_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_Code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_charging_ase_Code,
                                 NULL);

  return offset;
}


static const value_string charging_ase_CriticalityType_vals[] = {
  {   0, "ignore" },
  {   1, "abort" },
  { 0, NULL }
};


static int
dissect_charging_ase_CriticalityType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_charging_ase_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 14 "../../asn1/charging_ase/charging_ase.cnf"

	proto_tree_add_text(tree, tvb, offset, -1, "Extensions not dissected");
	return tvb_length(tvb);


  return offset;
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { &hf_charging_ase_type   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_charging_ase_Code },
  { &hf_charging_ase_criticality, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_charging_ase_CriticalityType },
  { &hf_charging_ase_value  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_charging_ase_ExtensionField);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField_sequence_of[1] = {
  { &hf_charging_ase_extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_charging_ase_ExtensionField },
};

static int
dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField_sequence_of, hf_index, ett_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField);

  return offset;
}



static int
dissect_charging_ase_NetworkIdentification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_charging_ase_ReferenceID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ChargingReferenceIdentification_sequence[] = {
  { &hf_charging_ase_networkIdentification, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_NetworkIdentification },
  { &hf_charging_ase_referenceID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_ReferenceID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_ChargingReferenceIdentification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChargingReferenceIdentification_sequence, hf_index, ett_charging_ase_ChargingReferenceIdentification);

  return offset;
}


static const value_string charging_ase_Currency_vals[] = {
  {   0, "noIndication" },
  {   1, "australianDollar" },
  {   2, "austrianSchilling" },
  {   3, "belgianFranc" },
  {   4, "britishPound" },
  {   5, "czechKoruna" },
  {   6, "danishKrone" },
  {   7, "dutchGuilder" },
  {   8, "euro" },
  {   9, "finnishMarkka" },
  {  10, "frenchFranc" },
  {  11, "germanMark" },
  {  12, "greekDrachma" },
  {  13, "hungarianForint" },
  {  14, "irishPunt" },
  {  15, "italianLira" },
  {  16, "japaneseYen" },
  {  17, "luxembourgian-Franc" },
  {  18, "norwegianKrone" },
  {  19, "polishZloty" },
  {  20, "portugeseEscudo" },
  {  21, "russianRouble" },
  {  22, "slovakKoruna" },
  {  23, "spanishPeseta" },
  {  24, "swedishKrone" },
  {  25, "swissFranc" },
  {  26, "turkishLira" },
  {  27, "uSDollar" },
  { 0, NULL }
};


static int
dissect_charging_ase_Currency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ChargingTariffInformation_sequence[] = {
  { &hf_charging_ase_chargingControlIndicators, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingControlIndicators },
  { &hf_charging_ase_chargingTariff, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_chargingTariff },
  { &hf_charging_ase_extensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField },
  { &hf_charging_ase_originationIdentification, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { &hf_charging_ase_destinationIdentification, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { &hf_charging_ase_currency, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_charging_ase_Currency },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_ChargingTariffInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChargingTariffInformation_sequence, hf_index, ett_charging_ase_ChargingTariffInformation);

  return offset;
}


static const value_string charging_ase_T_addOncharge_vals[] = {
  {   0, "addOnChargeCurrency" },
  {   1, "addOnChargePulse" },
  { 0, NULL }
};

static const ber_choice_t T_addOncharge_choice[] = {
  {   0, &hf_charging_ase_addOnChargeCurrency, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_CurrencyFactorScale },
  {   1, &hf_charging_ase_addOnChargePulse, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_PulseUnits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_T_addOncharge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_addOncharge_choice, hf_index, ett_charging_ase_T_addOncharge,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddOnChargingInformation_sequence[] = {
  { &hf_charging_ase_chargingControlIndicators, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingControlIndicators },
  { &hf_charging_ase_addOncharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_addOncharge },
  { &hf_charging_ase_extensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField },
  { &hf_charging_ase_originationIdentification, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { &hf_charging_ase_destinationIdentification, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { &hf_charging_ase_currency, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_charging_ase_Currency },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_AddOnChargingInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddOnChargingInformation_sequence, hf_index, ett_charging_ase_AddOnChargingInformation);

  return offset;
}


static const asn_namedbit T_acknowledgementIndicators_bits[] = {
  {  0, &hf_charging_ase_T_acknowledgementIndicators_accepted, -1, -1, "accepted", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_T_acknowledgementIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_acknowledgementIndicators_bits, hf_index, ett_charging_ase_T_acknowledgementIndicators,
                                    NULL);

  return offset;
}


static const ber_sequence_t ChargingAcknowledgementInformation_sequence[] = {
  { &hf_charging_ase_acknowledgementIndicators, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_acknowledgementIndicators },
  { &hf_charging_ase_extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField },
  { &hf_charging_ase_originationIdentification, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { &hf_charging_ase_destinationIdentification, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_ChargingAcknowledgementInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChargingAcknowledgementInformation_sequence, hf_index, ett_charging_ase_ChargingAcknowledgementInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification_sequence_of[1] = {
  { &hf_charging_ase_networkOperators_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_charging_ase_NetworkIdentification },
};

static int
dissect_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification_sequence_of, hf_index, ett_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification);

  return offset;
}


static const ber_sequence_t StartCharging_sequence[] = {
  { &hf_charging_ase_networkOperators, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification },
  { &hf_charging_ase_extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField },
  { &hf_charging_ase_originationIdentification, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_StartCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StartCharging_sequence, hf_index, ett_charging_ase_StartCharging);

  return offset;
}


static const asn_namedbit T_stopIndicators_bits[] = {
  {  0, &hf_charging_ase_T_stopIndicators_callAttemptChargesApplicable, -1, -1, "callAttemptChargesApplicable", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_charging_ase_T_stopIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_stopIndicators_bits, hf_index, ett_charging_ase_T_stopIndicators,
                                    NULL);

  return offset;
}


static const ber_sequence_t StopCharging_sequence[] = {
  { &hf_charging_ase_stopIndicators, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_T_stopIndicators },
  { &hf_charging_ase_networkOperators, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification },
  { &hf_charging_ase_extensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField },
  { &hf_charging_ase_originationIdentification, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingReferenceIdentification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_charging_ase_StopCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StopCharging_sequence, hf_index, ett_charging_ase_StopCharging);

  return offset;
}


const value_string charging_ase_ChargingMessageType_vals[] = {
  {   0, "crgt" },
  {   1, "aocrg" },
  {   2, "crga" },
  {   3, "start" },
  {   4, "stop" },
  { 0, NULL }
};

static const ber_choice_t ChargingMessageType_choice[] = {
  {   0, &hf_charging_ase_crgt   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingTariffInformation },
  {   1, &hf_charging_ase_aocrg  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_charging_ase_AddOnChargingInformation },
  {   2, &hf_charging_ase_crga   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_charging_ase_ChargingAcknowledgementInformation },
  {   3, &hf_charging_ase_start  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_charging_ase_StartCharging },
  {   4, &hf_charging_ase_stop   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_charging_ase_StopCharging },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_charging_ase_ChargingMessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingMessageType_choice, hf_index, ett_charging_ase_ChargingMessageType,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

int dissect_charging_ase_ChargingMessageType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_charging_ase_ChargingMessageType(FALSE, tvb, offset, &asn1_ctx, tree, hf_charging_ase_charging_ase_ChargingMessageType_PDU);
  return offset;
}


/*--- End of included file: packet-charging_ase-fn.c ---*/
#line 52 "../../asn1/charging_ase/packet-charging_ase-template.c"

static void
dissect_charging_ase(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *it;
    proto_tree *tr;

    it=proto_tree_add_protocol_format(tree, proto_charging_ase, tvb, 0, tvb_length(tvb), "Charging ASE");
    tr=proto_item_add_subtree(it, ett_charging_ase);

    if(tvb_length(tvb)>0)
    {
        dissect_charging_ase_ChargingMessageType_PDU(tvb , pinfo, tr);
    }
}

/* Register all the bits needed with the filtering engine */
void
proto_register_charging_ase(void)
{
  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-charging_ase-hfarr.c ---*/
#line 1 "../../asn1/charging_ase/packet-charging_ase-hfarr.c"
    { &hf_charging_ase_charging_ase_ChargingMessageType_PDU,
      { "ChargingMessageType", "charging_ase.ChargingMessageType",
        FT_UINT32, BASE_DEC, VALS(charging_ase_ChargingMessageType_vals), 0,
        NULL, HFILL }},
    { &hf_charging_ase_crgt,
      { "crgt", "charging_ase.crgt",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChargingTariffInformation", HFILL }},
    { &hf_charging_ase_aocrg,
      { "aocrg", "charging_ase.aocrg",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddOnChargingInformation", HFILL }},
    { &hf_charging_ase_crga,
      { "crga", "charging_ase.crga",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChargingAcknowledgementInformation", HFILL }},
    { &hf_charging_ase_start,
      { "start", "charging_ase.start",
        FT_NONE, BASE_NONE, NULL, 0,
        "StartCharging", HFILL }},
    { &hf_charging_ase_stop,
      { "stop", "charging_ase.stop",
        FT_NONE, BASE_NONE, NULL, 0,
        "StopCharging", HFILL }},
    { &hf_charging_ase_acknowledgementIndicators,
      { "acknowledgementIndicators", "charging_ase.acknowledgementIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_extensions,
      { "extensions", "charging_ase.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField", HFILL }},
    { &hf_charging_ase_extensions_item,
      { "ExtensionField", "charging_ase.ExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_originationIdentification,
      { "originationIdentification", "charging_ase.originationIdentification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChargingReferenceIdentification", HFILL }},
    { &hf_charging_ase_destinationIdentification,
      { "destinationIdentification", "charging_ase.destinationIdentification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ChargingReferenceIdentification", HFILL }},
    { &hf_charging_ase_chargingControlIndicators,
      { "chargingControlIndicators", "charging_ase.chargingControlIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_addOncharge,
      { "addOncharge", "charging_ase.addOncharge",
        FT_UINT32, BASE_DEC, VALS(charging_ase_T_addOncharge_vals), 0,
        NULL, HFILL }},
    { &hf_charging_ase_addOnChargeCurrency,
      { "addOnChargeCurrency", "charging_ase.addOnChargeCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrencyFactorScale", HFILL }},
    { &hf_charging_ase_addOnChargePulse,
      { "addOnChargePulse", "charging_ase.addOnChargePulse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PulseUnits", HFILL }},
    { &hf_charging_ase_currency,
      { "currency", "charging_ase.currency",
        FT_UINT32, BASE_DEC, VALS(charging_ase_Currency_vals), 0,
        NULL, HFILL }},
    { &hf_charging_ase_chargingTariff,
      { "chargingTariff", "charging_ase.chargingTariff",
        FT_UINT32, BASE_DEC, VALS(charging_ase_T_chargingTariff_vals), 0,
        NULL, HFILL }},
    { &hf_charging_ase_tariffCurrency,
      { "tariffCurrency", "charging_ase.tariffCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_tariffPulse,
      { "tariffPulse", "charging_ase.tariffPulse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_local,
      { "local", "charging_ase.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_charging_ase_global,
      { "global", "charging_ase.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_charging_ase_currencyFactorScale,
      { "currencyFactorScale", "charging_ase.currencyFactorScale",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_tariffDuration,
      { "tariffDuration", "charging_ase.tariffDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_subTariffControl,
      { "subTariffControl", "charging_ase.subTariffControl",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_pulseUnits,
      { "pulseUnits", "charging_ase.pulseUnits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_chargeUnitTimeInterval,
      { "chargeUnitTimeInterval", "charging_ase.chargeUnitTimeInterval",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_currencyFactor,
      { "currencyFactor", "charging_ase.currencyFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_currencyScale,
      { "currencyScale", "charging_ase.currencyScale",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_type,
      { "type", "charging_ase.type",
        FT_UINT32, BASE_DEC, VALS(charging_ase_Code_vals), 0,
        "Code", HFILL }},
    { &hf_charging_ase_criticality,
      { "criticality", "charging_ase.criticality",
        FT_UINT32, BASE_DEC, VALS(charging_ase_CriticalityType_vals), 0,
        "CriticalityType", HFILL }},
    { &hf_charging_ase_value,
      { "value", "charging_ase.value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_networkOperators,
      { "networkOperators", "charging_ase.networkOperators",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification", HFILL }},
    { &hf_charging_ase_networkOperators_item,
      { "NetworkIdentification", "charging_ase.NetworkIdentification",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_stopIndicators,
      { "stopIndicators", "charging_ase.stopIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_currentTariffCurrency,
      { "currentTariffCurrency", "charging_ase.currentTariffCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        "TariffCurrencyFormat", HFILL }},
    { &hf_charging_ase_tariffSwitchCurrency,
      { "tariffSwitchCurrency", "charging_ase.tariffSwitchCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_nextTariffCurrency,
      { "nextTariffCurrency", "charging_ase.nextTariffCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        "TariffCurrencyFormat", HFILL }},
    { &hf_charging_ase_tariffSwitchoverTime,
      { "tariffSwitchoverTime", "charging_ase.tariffSwitchoverTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_communicationChargeSequenceCurrency,
      { "communicationChargeSequenceCurrency", "charging_ase.communicationChargeSequenceCurrency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency", HFILL }},
    { &hf_charging_ase_communicationChargeSequenceCurrency_item,
      { "CommunicationChargeCurrency", "charging_ase.CommunicationChargeCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_tariffControlIndicators,
      { "tariffControlIndicators", "charging_ase.tariffControlIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_callAttemptChargeCurrency,
      { "callAttemptChargeCurrency", "charging_ase.callAttemptChargeCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrencyFactorScale", HFILL }},
    { &hf_charging_ase_callSetupChargeCurrency,
      { "callSetupChargeCurrency", "charging_ase.callSetupChargeCurrency",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrencyFactorScale", HFILL }},
    { &hf_charging_ase_currentTariffPulse,
      { "currentTariffPulse", "charging_ase.currentTariffPulse",
        FT_NONE, BASE_NONE, NULL, 0,
        "TariffPulseFormat", HFILL }},
    { &hf_charging_ase_tariffSwitchPulse,
      { "tariffSwitchPulse", "charging_ase.tariffSwitchPulse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_nextTariffPulse,
      { "nextTariffPulse", "charging_ase.nextTariffPulse",
        FT_NONE, BASE_NONE, NULL, 0,
        "TariffPulseFormat", HFILL }},
    { &hf_charging_ase_communicationChargeSequencePulse,
      { "communicationChargeSequencePulse", "charging_ase.communicationChargeSequencePulse",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse", HFILL }},
    { &hf_charging_ase_communicationChargeSequencePulse_item,
      { "CommunicationChargePulse", "charging_ase.CommunicationChargePulse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_tariffControlIndicators_01,
      { "tariffControlIndicators", "charging_ase.tariffControlIndicators",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_tariffControlIndicators_01", HFILL }},
    { &hf_charging_ase_callAttemptChargePulse,
      { "callAttemptChargePulse", "charging_ase.callAttemptChargePulse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PulseUnits", HFILL }},
    { &hf_charging_ase_callSetupChargePulse,
      { "callSetupChargePulse", "charging_ase.callSetupChargePulse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PulseUnits", HFILL }},
    { &hf_charging_ase_networkIdentification,
      { "networkIdentification", "charging_ase.networkIdentification",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_referenceID,
      { "referenceID", "charging_ase.referenceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_charging_ase_T_acknowledgementIndicators_accepted,
      { "accepted", "charging_ase.accepted",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_charging_ase_ChargingControlIndicators_subscriberCharge,
      { "subscriberCharge", "charging_ase.subscriberCharge",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_charging_ase_ChargingControlIndicators_immediateChangeOfActuallyAppliedTariff,
      { "immediateChangeOfActuallyAppliedTariff", "charging_ase.immediateChangeOfActuallyAppliedTariff",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_charging_ase_ChargingControlIndicators_delayUntilStart,
      { "delayUntilStart", "charging_ase.delayUntilStart",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_charging_ase_T_stopIndicators_callAttemptChargesApplicable,
      { "callAttemptChargesApplicable", "charging_ase.callAttemptChargesApplicable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_charging_ase_SubTariffControl_oneTimeCharge,
      { "oneTimeCharge", "charging_ase.oneTimeCharge",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_charging_ase_T_tariffControlIndicators_non_cyclicTariff,
      { "non-cyclicTariff", "charging_ase.non-cyclicTariff",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_charging_ase_T_tariffControlIndicators_01_non_cyclicTariff,
      { "non-cyclicTariff", "charging_ase.non-cyclicTariff",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

/*--- End of included file: packet-charging_ase-hfarr.c ---*/
#line 75 "../../asn1/charging_ase/packet-charging_ase-template.c"
  };

  /* List of subtrees */
    static gint *ett[] = {
    &ett_charging_ase,

/*--- Included file: packet-charging_ase-ettarr.c ---*/
#line 1 "../../asn1/charging_ase/packet-charging_ase-ettarr.c"
    &ett_charging_ase_ChargingMessageType,
    &ett_charging_ase_ChargingAcknowledgementInformation,
    &ett_charging_ase_T_acknowledgementIndicators,
    &ett_charging_ase_SEQUENCE_SIZE_1_numOfExtensions_OF_ExtensionField,
    &ett_charging_ase_ChargingControlIndicators,
    &ett_charging_ase_AddOnChargingInformation,
    &ett_charging_ase_T_addOncharge,
    &ett_charging_ase_ChargingTariffInformation,
    &ett_charging_ase_T_chargingTariff,
    &ett_charging_ase_Code,
    &ett_charging_ase_CommunicationChargeCurrency,
    &ett_charging_ase_CommunicationChargePulse,
    &ett_charging_ase_CurrencyFactorScale,
    &ett_charging_ase_ExtensionField,
    &ett_charging_ase_StartCharging,
    &ett_charging_ase_SEQUENCE_SIZE_1_maxNetworkOperators_OF_NetworkIdentification,
    &ett_charging_ase_StopCharging,
    &ett_charging_ase_T_stopIndicators,
    &ett_charging_ase_SubTariffControl,
    &ett_charging_ase_TariffCurrency,
    &ett_charging_ase_TariffSwitchCurrency,
    &ett_charging_ase_TariffCurrencyFormat,
    &ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargeCurrency,
    &ett_charging_ase_T_tariffControlIndicators,
    &ett_charging_ase_TariffPulse,
    &ett_charging_ase_TariffSwitchPulse,
    &ett_charging_ase_TariffPulseFormat,
    &ett_charging_ase_SEQUENCE_SIZE_minCommunicationTariffNum_maxCommunicationTariffNum_OF_CommunicationChargePulse,
    &ett_charging_ase_T_tariffControlIndicators_01,
    &ett_charging_ase_ChargingReferenceIdentification,

/*--- End of included file: packet-charging_ase-ettarr.c ---*/
#line 81 "../../asn1/charging_ase/packet-charging_ase-template.c"
        };

  proto_charging_ase = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_charging_ase, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */
void
proto_reg_handoff_charging_ase(void)
{
  charging_ase_handle = create_dissector_handle(dissect_charging_ase, proto_charging_ase);
}

