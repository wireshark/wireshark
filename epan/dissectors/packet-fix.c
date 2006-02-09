/* packet-fix.c
 * Routines for Financial Information eXchange (FIX) Protocol dissection
 * Copyright 2000, PC Drew <drewpc@ibsncentral.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Documentation: http://www.fixprotocol.org/
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static const value_string message_types[] = {
      { 0x30, "Heartbeat" },
      { 0x31, "Test Request" },
      { 0x32, "Resend Request" },
      { 0x33, "Reject" },
      { 0x34, "Sequence Reset" },
      { 0x35, "Logout" },
      { 0x36, "Indication of Interest" },
      { 0x37, "Advertisement" },
      { 0x38, "Execution Report" },
      { 0x39, "Cancel Reject" },
      { 0x41, "Logon" },
      { 0x42, "News" },
      { 0x43, "Email" },
      { 0x44, "New Order - Single" },
      { 0x45, "New Order - List" },
      { 0x46, "Order Cancel Request" },
      { 0x47, "Order Cancel/Replace Request" },
      { 0x48, "Order Status Request" },
      { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_fix = -1;

/* Initialize the subtree pointers */
static gint ett_fix = -1;

/* message type list */
static GData *msg_types;

static int hf_fix_Account = -1; /* Tag 1 */
static int hf_fix_AdvId = -1; /* Tag 2 */
static int hf_fix_AdvRefID = -1; /* Tag 3 */
static int hf_fix_AdvSide = -1; /* Tag 4 */
static int hf_fix_AdvTransType = -1; /* Tag 5 */
static int hf_fix_AvgPx = -1; /* Tag 6 */
static int hf_fix_BeginSeqNo = -1; /* Tag 7 */
static int hf_fix_BeginString = -1; /* Tag 8 */
static int hf_fix_BodyLength = -1; /* Tag 9 */
static int hf_fix_CheckSum = -1; /* Tag 10 */
static int hf_fix_ClOrdID = -1; /* Tag 11 */
static int hf_fix_Commission = -1; /* Tag 12 */
static int hf_fix_CommType = -1; /* Tag 13 */
static int hf_fix_CumQty = -1; /* Tag 14 */
static int hf_fix_Currency = -1; /* Tag 15 */
static int hf_fix_EndSeqNo = -1; /* Tag 16 */
static int hf_fix_ExecID = -1; /* Tag 17 */
static int hf_fix_ExecInst = -1; /* Tag 18 */
static int hf_fix_ExecRefID = -1; /* Tag 19 */
static int hf_fix_ExecTransType = -1; /* Tag 20 */
static int hf_fix_HandlInst = -1; /* Tag 21 */
static int hf_fix_SecurityIDSource = -1; /* Tag 22 */
static int hf_fix_IOIid = -1; /* Tag 23 */
static int hf_fix_IOIOthSvc = -1; /* Tag 24 */
static int hf_fix_IOIQltyInd = -1; /* Tag 25 */
static int hf_fix_IOIRefID = -1; /* Tag 26 */
static int hf_fix_IOIQty = -1; /* Tag 27 */
static int hf_fix_IOITransType = -1; /* Tag 28 */
static int hf_fix_LastCapacity = -1; /* Tag 29 */
static int hf_fix_LastMkt = -1; /* Tag 30 */
static int hf_fix_LastPx = -1; /* Tag 31 */
static int hf_fix_LastQty = -1; /* Tag 32 */
static int hf_fix_LinesOfText = -1; /* Tag 33 */
static int hf_fix_MsgSeqNum = -1; /* Tag 34 */
static int hf_fix_MsgType = -1; /* Tag 35 */
static int hf_fix_NewSeqNo = -1; /* Tag 36 */
static int hf_fix_OrderID = -1; /* Tag 37 */
static int hf_fix_OrderQty = -1; /* Tag 38 */
static int hf_fix_OrdStatus = -1; /* Tag 39 */
static int hf_fix_OrdType = -1; /* Tag 40 */
static int hf_fix_OrigClOrdID = -1; /* Tag 41 */
static int hf_fix_OrigTime = -1; /* Tag 42 */
static int hf_fix_PossDupFlag = -1; /* Tag 43 */
static int hf_fix_Price = -1; /* Tag 44 */
static int hf_fix_RefSeqNum = -1; /* Tag 45 */
static int hf_fix_RelatdSym = -1; /* Tag 46 */
static int hf_fix_Rule80A = -1; /* Tag 47 */
static int hf_fix_SecurityID = -1; /* Tag 48 */
static int hf_fix_SenderCompID = -1; /* Tag 49 */
static int hf_fix_SenderSubID = -1; /* Tag 50 */
static int hf_fix_SendingDate = -1; /* Tag 51 */
static int hf_fix_SendingTime = -1; /* Tag 52 */
static int hf_fix_Quantity = -1; /* Tag 53 */
static int hf_fix_Side = -1; /* Tag 54 */
static int hf_fix_Symbol = -1; /* Tag 55 */
static int hf_fix_TargetCompID = -1; /* Tag 56 */
static int hf_fix_TargetSubID = -1; /* Tag 57 */
static int hf_fix_Text = -1; /* Tag 58 */
static int hf_fix_TimeInForce = -1; /* Tag 59 */
static int hf_fix_TransactTime = -1; /* Tag 60 */
static int hf_fix_Urgency = -1; /* Tag 61 */
static int hf_fix_ValidUntilTime = -1; /* Tag 62 */
static int hf_fix_SettlmntTyp = -1; /* Tag 63 */
static int hf_fix_FutSettDate = -1; /* Tag 64 */
static int hf_fix_SymbolSfx = -1; /* Tag 65 */
static int hf_fix_ListID = -1; /* Tag 66 */
static int hf_fix_ListSeqNo = -1; /* Tag 67 */
static int hf_fix_TotNoOrders = -1; /* Tag 68 */
static int hf_fix_ListExecInst = -1; /* Tag 69 */
static int hf_fix_AllocID = -1; /* Tag 70 */
static int hf_fix_AllocTransType = -1; /* Tag 71 */
static int hf_fix_RefAllocID = -1; /* Tag 72 */
static int hf_fix_NoOrders = -1; /* Tag 73 */
static int hf_fix_AvgPrxPrecision = -1; /* Tag 74 */
static int hf_fix_TradeDate = -1; /* Tag 75 */
static int hf_fix_ExecBroker = -1; /* Tag 76 */
static int hf_fix_PositionEffect = -1; /* Tag 77 */
static int hf_fix_NoAllocs = -1; /* Tag 78 */
static int hf_fix_AllocAccount = -1; /* Tag 79 */
static int hf_fix_AllocQty = -1; /* Tag 80 */
static int hf_fix_ProcessCode = -1; /* Tag 81 */
static int hf_fix_NoRpts = -1; /* Tag 82 */
static int hf_fix_RptSeq = -1; /* Tag 83 */
static int hf_fix_CxlQty = -1; /* Tag 84 */
static int hf_fix_NoDlvyInst = -1; /* Tag 85 */
static int hf_fix_DlvyInst = -1; /* Tag 86 */
static int hf_fix_AllocStatus = -1; /* Tag 87 */
static int hf_fix_AllocRejCode = -1; /* Tag 88 */
static int hf_fix_Signature = -1; /* Tag 89 */
static int hf_fix_SecureDataLen = -1; /* Tag 90 */
static int hf_fix_SecureData = -1; /* Tag 91 */
static int hf_fix_BrokerOfCredit = -1; /* Tag 92 */
static int hf_fix_SignatureLength = -1; /* Tag 93 */
static int hf_fix_EmailType = -1; /* Tag 94 */
static int hf_fix_RawDataLength = -1; /* Tag 95 */
static int hf_fix_RawData = -1; /* Tag 96 */
static int hf_fix_PossResend = -1; /* Tag 97 */
static int hf_fix_EncryptMethod = -1; /* Tag 98 */
static int hf_fix_StopPx = -1; /* Tag 99 */
static int hf_fix_ExDestination = -1; /* Tag 100 */
static int hf_fix_CxlRejReason = -1; /* Tag 102 */
static int hf_fix_OrdRejReason = -1; /* Tag 103 */
static int hf_fix_IOIQualifier = -1; /* Tag 104 */
static int hf_fix_WaveNo = -1; /* Tag 105 */
static int hf_fix_Issuer = -1; /* Tag 106 */
static int hf_fix_SecurityDesc = -1; /* Tag 107 */
static int hf_fix_HeartBtInt = -1; /* Tag 108 */
static int hf_fix_ClientID = -1; /* Tag 109 */
static int hf_fix_MinQty = -1; /* Tag 110 */
static int hf_fix_MaxFloor = -1; /* Tag 111 */
static int hf_fix_TestReqID = -1; /* Tag 112 */
static int hf_fix_ReportToExch = -1; /* Tag 113 */
static int hf_fix_LocateReqd = -1; /* Tag 114 */
static int hf_fix_OnBehalfOfCompID = -1; /* Tag 115 */
static int hf_fix_OnBehalfOfSubID = -1; /* Tag 116 */
static int hf_fix_QuoteID = -1; /* Tag 117 */
static int hf_fix_NetMoney = -1; /* Tag 118 */
static int hf_fix_SettlCurrAmt = -1; /* Tag 119 */
static int hf_fix_SettlCurrency = -1; /* Tag 120 */
static int hf_fix_ForexReq = -1; /* Tag 121 */
static int hf_fix_OrigSendingTime = -1; /* Tag 122 */
static int hf_fix_GapFillFlag = -1; /* Tag 123 */
static int hf_fix_NoExecs = -1; /* Tag 124 */
static int hf_fix_CxlType = -1; /* Tag 125 */
static int hf_fix_ExpireTime = -1; /* Tag 126 */
static int hf_fix_DKReason = -1; /* Tag 127 */
static int hf_fix_DeliverToCompID = -1; /* Tag 128 */
static int hf_fix_DeliverToSubID = -1; /* Tag 129 */
static int hf_fix_IOINaturalFlag = -1; /* Tag 130 */
static int hf_fix_QuoteReqID = -1; /* Tag 131 */
static int hf_fix_BidPx = -1; /* Tag 132 */
static int hf_fix_OfferPx = -1; /* Tag 133 */
static int hf_fix_BidSize = -1; /* Tag 134 */
static int hf_fix_OfferSize = -1; /* Tag 135 */
static int hf_fix_NoMiscFees = -1; /* Tag 136 */
static int hf_fix_MiscFeeAmt = -1; /* Tag 137 */
static int hf_fix_MiscFeeCurr = -1; /* Tag 138 */
static int hf_fix_MiscFeeType = -1; /* Tag 139 */
static int hf_fix_PrevClosePx = -1; /* Tag 140 */
static int hf_fix_ResetSeqNumFlag = -1; /* Tag 141 */
static int hf_fix_SenderLocationID = -1; /* Tag 142 */
static int hf_fix_TargetLocationID = -1; /* Tag 143 */
static int hf_fix_OnBehalfOfLocationID = -1; /* Tag 144 */
static int hf_fix_DeliverToLocationID = -1; /* Tag 145 */
static int hf_fix_NoRelatedSym = -1; /* Tag 146 */
static int hf_fix_Subject = -1; /* Tag 147 */
static int hf_fix_Headline = -1; /* Tag 148 */
static int hf_fix_URLLink = -1; /* Tag 149 */
static int hf_fix_ExecType = -1; /* Tag 150 */
static int hf_fix_LeavesQty = -1; /* Tag 151 */
static int hf_fix_CashOrderQty = -1; /* Tag 152 */
static int hf_fix_AllocAvgPx = -1; /* Tag 153 */
static int hf_fix_AllocNetMoney = -1; /* Tag 154 */
static int hf_fix_SettlCurrFxRate = -1; /* Tag 155 */
static int hf_fix_SettlCurrFxRateCalc = -1; /* Tag 156 */
static int hf_fix_NumDaysInterest = -1; /* Tag 157 */
static int hf_fix_AccruedInterestRate = -1; /* Tag 158 */
static int hf_fix_AccruedInterestAmt = -1; /* Tag 159 */
static int hf_fix_SettlInstMode = -1; /* Tag 160 */
static int hf_fix_AllocText = -1; /* Tag 161 */
static int hf_fix_SettlInstID = -1; /* Tag 162 */
static int hf_fix_SettlInstTransType = -1; /* Tag 163 */
static int hf_fix_EmailThreadID = -1; /* Tag 164 */
static int hf_fix_SettlInstSource = -1; /* Tag 165 */
static int hf_fix_SettlLocation = -1; /* Tag 166 */
static int hf_fix_SecurityType = -1; /* Tag 167 */
static int hf_fix_EffectiveTime = -1; /* Tag 168 */
static int hf_fix_StandInstDbType = -1; /* Tag 169 */
static int hf_fix_StandInstDbName = -1; /* Tag 170 */
static int hf_fix_StandInstDbID = -1; /* Tag 171 */
static int hf_fix_SettlDeliveryType = -1; /* Tag 172 */
static int hf_fix_SettlDepositoryCode = -1; /* Tag 173 */
static int hf_fix_SettlBrkrCode = -1; /* Tag 174 */
static int hf_fix_SettlInstCode = -1; /* Tag 175 */
static int hf_fix_SecuritySettlAgentName = -1; /* Tag 176 */
static int hf_fix_SecuritySettlAgentCode = -1; /* Tag 177 */
static int hf_fix_SecuritySettlAgentAcctNum = -1; /* Tag 178 */
static int hf_fix_SecuritySettlAgentAcctName = -1; /* Tag 179 */
static int hf_fix_SecuritySettlAgentContactName = -1; /* Tag 180 */
static int hf_fix_SecuritySettlAgentContactPhone = -1; /* Tag 181 */
static int hf_fix_CashSettlAgentName = -1; /* Tag 182 */
static int hf_fix_CashSettlAgentCode = -1; /* Tag 183 */
static int hf_fix_CashSettlAgentAcctNum = -1; /* Tag 184 */
static int hf_fix_CashSettlAgentAcctName = -1; /* Tag 185 */
static int hf_fix_CashSettlAgentContactName = -1; /* Tag 186 */
static int hf_fix_CashSettlAgentContactPhone = -1; /* Tag 187 */
static int hf_fix_BidSpotRate = -1; /* Tag 188 */
static int hf_fix_BidForwardPoints = -1; /* Tag 189 */
static int hf_fix_OfferSpotRate = -1; /* Tag 190 */
static int hf_fix_OfferForwardPoints = -1; /* Tag 191 */
static int hf_fix_OrderQty2 = -1; /* Tag 192 */
static int hf_fix_FutSettDate2 = -1; /* Tag 193 */
static int hf_fix_LastSpotRate = -1; /* Tag 194 */
static int hf_fix_LastForwardPoints = -1; /* Tag 195 */
static int hf_fix_AllocLinkID = -1; /* Tag 196 */
static int hf_fix_AllocLinkType = -1; /* Tag 197 */
static int hf_fix_SecondaryOrderID = -1; /* Tag 198 */
static int hf_fix_NoIOIQualifiers = -1; /* Tag 199 */
static int hf_fix_MaturityMonthYear = -1; /* Tag 200 */
static int hf_fix_PutOrCall = -1; /* Tag 201 */
static int hf_fix_StrikePrice = -1; /* Tag 202 */
static int hf_fix_CoveredOrUncovered = -1; /* Tag 203 */
static int hf_fix_CustomerOrFirm = -1; /* Tag 204 */
static int hf_fix_MaturityDay = -1; /* Tag 205 */
static int hf_fix_OptAttribute = -1; /* Tag 206 */
static int hf_fix_SecurityExchange = -1; /* Tag 207 */
static int hf_fix_NotifyBrokerOfCredit = -1; /* Tag 208 */
static int hf_fix_AllocHandlInst = -1; /* Tag 209 */
static int hf_fix_MaxShow = -1; /* Tag 210 */
static int hf_fix_PegDifference = -1; /* Tag 211 */
static int hf_fix_XmlDataLen = -1; /* Tag 212 */
static int hf_fix_XmlData = -1; /* Tag 213 */
static int hf_fix_SettlInstRefID = -1; /* Tag 214 */
static int hf_fix_NoRoutingIDs = -1; /* Tag 215 */
static int hf_fix_RoutingType = -1; /* Tag 216 */
static int hf_fix_RoutingID = -1; /* Tag 217 */
static int hf_fix_Spread = -1; /* Tag 218 */
static int hf_fix_Benchmark = -1; /* Tag 219 */
static int hf_fix_BenchmarkCurveCurrency = -1; /* Tag 220 */
static int hf_fix_BenchmarkCurveName = -1; /* Tag 221 */
static int hf_fix_BenchmarkCurvePoint = -1; /* Tag 222 */
static int hf_fix_CouponRate = -1; /* Tag 223 */
static int hf_fix_CouponPaymentDate = -1; /* Tag 224 */
static int hf_fix_IssueDate = -1; /* Tag 225 */
static int hf_fix_RepurchaseTerm = -1; /* Tag 226 */
static int hf_fix_RepurchaseRate = -1; /* Tag 227 */
static int hf_fix_Factor = -1; /* Tag 228 */
static int hf_fix_TradeOriginationDate = -1; /* Tag 229 */
static int hf_fix_ExDate = -1; /* Tag 230 */
static int hf_fix_ContractMultiplier = -1; /* Tag 231 */
static int hf_fix_NoStipulations = -1; /* Tag 232 */
static int hf_fix_StipulationType = -1; /* Tag 233 */
static int hf_fix_StipulationValue = -1; /* Tag 234 */
static int hf_fix_YieldType = -1; /* Tag 235 */
static int hf_fix_Yield = -1; /* Tag 236 */
static int hf_fix_TotalTakedown = -1; /* Tag 237 */
static int hf_fix_Concession = -1; /* Tag 238 */
static int hf_fix_RepoCollateralSecurityType = -1; /* Tag 239 */
static int hf_fix_RedemptionDate = -1; /* Tag 240 */
static int hf_fix_UnderlyingCouponPaymentDate = -1; /* Tag 241 */
static int hf_fix_UnderlyingIssueDate = -1; /* Tag 242 */
static int hf_fix_UnderlyingRepoCollateralSecurityType = -1; /* Tag 243 */
static int hf_fix_UnderlyingRepurchaseTerm = -1; /* Tag 244 */
static int hf_fix_UnderlyingRepurchaseRate = -1; /* Tag 245 */
static int hf_fix_UnderlyingFactor = -1; /* Tag 246 */
static int hf_fix_UnderlyingRedemptionDate = -1; /* Tag 247 */
static int hf_fix_LegCouponPaymentDate = -1; /* Tag 248 */
static int hf_fix_LegIssueDate = -1; /* Tag 249 */
static int hf_fix_LegRepoCollateralSecurityType = -1; /* Tag 250 */
static int hf_fix_LegRepurchaseTerm = -1; /* Tag 251 */
static int hf_fix_LegRepurchaseRate = -1; /* Tag 252 */
static int hf_fix_LegFactor = -1; /* Tag 253 */
static int hf_fix_LegRedemptionDate = -1; /* Tag 254 */
static int hf_fix_CreditRating = -1; /* Tag 255 */
static int hf_fix_UnderlyingCreditRating = -1; /* Tag 256 */
static int hf_fix_LegCreditRating = -1; /* Tag 257 */
static int hf_fix_TradedFlatSwitch = -1; /* Tag 258 */
static int hf_fix_BasisFeatureDate = -1; /* Tag 259 */
static int hf_fix_BasisFeaturePrice = -1; /* Tag 260 */
static int hf_fix_ReservedAllocated = -1; /* Tag 261 */
static int hf_fix_MDReqID = -1; /* Tag 262 */
static int hf_fix_SubscriptionRequestType = -1; /* Tag 263 */
static int hf_fix_MarketDepth = -1; /* Tag 264 */
static int hf_fix_MDUpdateType = -1; /* Tag 265 */
static int hf_fix_AggregatedBook = -1; /* Tag 266 */
static int hf_fix_NoMDEntryTypes = -1; /* Tag 267 */
static int hf_fix_NoMDEntries = -1; /* Tag 268 */
static int hf_fix_MDEntryType = -1; /* Tag 269 */
static int hf_fix_MDEntryPx = -1; /* Tag 270 */
static int hf_fix_MDEntrySize = -1; /* Tag 271 */
static int hf_fix_MDEntryDate = -1; /* Tag 272 */
static int hf_fix_MDEntryTime = -1; /* Tag 273 */
static int hf_fix_TickDirection = -1; /* Tag 274 */
static int hf_fix_MDMkt = -1; /* Tag 275 */
static int hf_fix_QuoteCondition = -1; /* Tag 276 */
static int hf_fix_TradeCondition = -1; /* Tag 277 */
static int hf_fix_MDEntryID = -1; /* Tag 278 */
static int hf_fix_MDUpdateAction = -1; /* Tag 279 */
static int hf_fix_MDEntryRefID = -1; /* Tag 280 */
static int hf_fix_MDReqRejReason = -1; /* Tag 281 */
static int hf_fix_MDEntryOriginator = -1; /* Tag 282 */
static int hf_fix_LocationID = -1; /* Tag 283 */
static int hf_fix_DeskID = -1; /* Tag 284 */
static int hf_fix_DeleteReason = -1; /* Tag 285 */
static int hf_fix_OpenCloseSettleFlag = -1; /* Tag 286 */
static int hf_fix_SellerDays = -1; /* Tag 287 */
static int hf_fix_MDEntryBuyer = -1; /* Tag 288 */
static int hf_fix_MDEntrySeller = -1; /* Tag 289 */
static int hf_fix_MDEntryPositionNo = -1; /* Tag 290 */
static int hf_fix_FinancialStatus = -1; /* Tag 291 */
static int hf_fix_CorporateAction = -1; /* Tag 292 */
static int hf_fix_DefBidSize = -1; /* Tag 293 */
static int hf_fix_DefOfferSize = -1; /* Tag 294 */
static int hf_fix_NoQuoteEntries = -1; /* Tag 295 */
static int hf_fix_NoQuoteSets = -1; /* Tag 296 */
static int hf_fix_QuoteStatus = -1; /* Tag 297 */
static int hf_fix_QuoteCancelType = -1; /* Tag 298 */
static int hf_fix_QuoteEntryID = -1; /* Tag 299 */
static int hf_fix_QuoteRejectReason = -1; /* Tag 300 */
static int hf_fix_QuoteResponseLevel = -1; /* Tag 301 */
static int hf_fix_QuoteSetID = -1; /* Tag 302 */
static int hf_fix_QuoteRequestType = -1; /* Tag 303 */
static int hf_fix_TotQuoteEntries = -1; /* Tag 304 */
static int hf_fix_UnderlyingSecurityIDSource = -1; /* Tag 305 */
static int hf_fix_UnderlyingIssuer = -1; /* Tag 306 */
static int hf_fix_UnderlyingSecurityDesc = -1; /* Tag 307 */
static int hf_fix_UnderlyingSecurityExchange = -1; /* Tag 308 */
static int hf_fix_UnderlyingSecurityID = -1; /* Tag 309 */
static int hf_fix_UnderlyingSecurityType = -1; /* Tag 310 */
static int hf_fix_UnderlyingSymbol = -1; /* Tag 311 */
static int hf_fix_UnderlyingSymbolSfx = -1; /* Tag 312 */
static int hf_fix_UnderlyingMaturityMonthYear = -1; /* Tag 313 */
static int hf_fix_UnderlyingMaturityDay = -1; /* Tag 314 */
static int hf_fix_UnderlyingPutOrCall = -1; /* Tag 315 */
static int hf_fix_UnderlyingStrikePrice = -1; /* Tag 316 */
static int hf_fix_UnderlyingOptAttribute = -1; /* Tag 317 */
static int hf_fix_Underlying = -1; /* Tag 318 */
static int hf_fix_RatioQty = -1; /* Tag 319 */
static int hf_fix_SecurityReqID = -1; /* Tag 320 */
static int hf_fix_SecurityRequestType = -1; /* Tag 321 */
static int hf_fix_SecurityResponseID = -1; /* Tag 322 */
static int hf_fix_SecurityResponseType = -1; /* Tag 323 */
static int hf_fix_SecurityStatusReqID = -1; /* Tag 324 */
static int hf_fix_UnsolicitedIndicator = -1; /* Tag 325 */
static int hf_fix_SecurityTradingStatus = -1; /* Tag 326 */
static int hf_fix_HaltReason = -1; /* Tag 327 */
static int hf_fix_InViewOfCommon = -1; /* Tag 328 */
static int hf_fix_DueToRelated = -1; /* Tag 329 */
static int hf_fix_BuyVolume = -1; /* Tag 330 */
static int hf_fix_SellVolume = -1; /* Tag 331 */
static int hf_fix_HighPx = -1; /* Tag 332 */
static int hf_fix_LowPx = -1; /* Tag 333 */
static int hf_fix_Adjustment = -1; /* Tag 334 */
static int hf_fix_TradSesReqID = -1; /* Tag 335 */
static int hf_fix_TradingSessionID = -1; /* Tag 336 */
static int hf_fix_ContraTrader = -1; /* Tag 337 */
static int hf_fix_TradSesMethod = -1; /* Tag 338 */
static int hf_fix_TradSesMode = -1; /* Tag 339 */
static int hf_fix_TradSesStatus = -1; /* Tag 340 */
static int hf_fix_TradSesStartTime = -1; /* Tag 341 */
static int hf_fix_TradSesOpenTime = -1; /* Tag 342 */
static int hf_fix_TradSesPreCloseTime = -1; /* Tag 343 */
static int hf_fix_TradSesCloseTime = -1; /* Tag 344 */
static int hf_fix_TradSesEndTime = -1; /* Tag 345 */
static int hf_fix_NumberOfOrders = -1; /* Tag 346 */
static int hf_fix_MessageEncoding = -1; /* Tag 347 */
static int hf_fix_EncodedIssuerLen = -1; /* Tag 348 */
static int hf_fix_EncodedIssuer = -1; /* Tag 349 */
static int hf_fix_EncodedSecurityDescLen = -1; /* Tag 350 */
static int hf_fix_EncodedSecurityDesc = -1; /* Tag 351 */
static int hf_fix_EncodedListExecInstLen = -1; /* Tag 352 */
static int hf_fix_EncodedListExecInst = -1; /* Tag 353 */
static int hf_fix_EncodedTextLen = -1; /* Tag 354 */
static int hf_fix_EncodedText = -1; /* Tag 355 */
static int hf_fix_EncodedSubjectLen = -1; /* Tag 356 */
static int hf_fix_EncodedSubject = -1; /* Tag 357 */
static int hf_fix_EncodedHeadlineLen = -1; /* Tag 358 */
static int hf_fix_EncodedHeadline = -1; /* Tag 359 */
static int hf_fix_EncodedAllocTextLen = -1; /* Tag 360 */
static int hf_fix_EncodedAllocText = -1; /* Tag 361 */
static int hf_fix_EncodedUnderlyingIssuerLen = -1; /* Tag 362 */
static int hf_fix_EncodedUnderlyingIssuer = -1; /* Tag 363 */
static int hf_fix_EncodedUnderlyingSecurityDescLen = -1; /* Tag 364 */
static int hf_fix_EncodedUnderlyingSecurityDesc = -1; /* Tag 365 */
static int hf_fix_AllocPrice = -1; /* Tag 366 */
static int hf_fix_QuoteSetValidUntilTime = -1; /* Tag 367 */
static int hf_fix_QuoteEntryRejectReason = -1; /* Tag 368 */
static int hf_fix_LastMsgSeqNumProcessed = -1; /* Tag 369 */
static int hf_fix_OnBehalfOfSendingTime = -1; /* Tag 370 */
static int hf_fix_RefTagID = -1; /* Tag 371 */
static int hf_fix_RefMsgType = -1; /* Tag 372 */
static int hf_fix_SessionRejectReason = -1; /* Tag 373 */
static int hf_fix_BidRequestTransType = -1; /* Tag 374 */
static int hf_fix_ContraBroker = -1; /* Tag 375 */
static int hf_fix_ComplianceID = -1; /* Tag 376 */
static int hf_fix_SolicitedFlag = -1; /* Tag 377 */
static int hf_fix_ExecRestatementReason = -1; /* Tag 378 */
static int hf_fix_BusinessRejectRefID = -1; /* Tag 379 */
static int hf_fix_BusinessRejectReason = -1; /* Tag 380 */
static int hf_fix_GrossTradeAmt = -1; /* Tag 381 */
static int hf_fix_NoContraBrokers = -1; /* Tag 382 */
static int hf_fix_MaxMessageSize = -1; /* Tag 383 */
static int hf_fix_NoMsgTypes = -1; /* Tag 384 */
static int hf_fix_MsgDirection = -1; /* Tag 385 */
static int hf_fix_NoTradingSessions = -1; /* Tag 386 */
static int hf_fix_TotalVolumeTraded = -1; /* Tag 387 */
static int hf_fix_DiscretionInst = -1; /* Tag 388 */
static int hf_fix_DiscretionOffset = -1; /* Tag 389 */
static int hf_fix_BidID = -1; /* Tag 390 */
static int hf_fix_ClientBidID = -1; /* Tag 391 */
static int hf_fix_ListName = -1; /* Tag 392 */
static int hf_fix_TotalNumSecurities = -1; /* Tag 393 */
static int hf_fix_BidType = -1; /* Tag 394 */
static int hf_fix_NumTickets = -1; /* Tag 395 */
static int hf_fix_SideValue1 = -1; /* Tag 396 */
static int hf_fix_SideValue2 = -1; /* Tag 397 */
static int hf_fix_NoBidDescriptors = -1; /* Tag 398 */
static int hf_fix_BidDescriptorType = -1; /* Tag 399 */
static int hf_fix_BidDescriptor = -1; /* Tag 400 */
static int hf_fix_SideValueInd = -1; /* Tag 401 */
static int hf_fix_LiquidityPctLow = -1; /* Tag 402 */
static int hf_fix_LiquidityPctHigh = -1; /* Tag 403 */
static int hf_fix_LiquidityValue = -1; /* Tag 404 */
static int hf_fix_EFPTrackingError = -1; /* Tag 405 */
static int hf_fix_FairValue = -1; /* Tag 406 */
static int hf_fix_OutsideIndexPct = -1; /* Tag 407 */
static int hf_fix_ValueOfFutures = -1; /* Tag 408 */
static int hf_fix_LiquidityIndType = -1; /* Tag 409 */
static int hf_fix_WtAverageLiquidity = -1; /* Tag 410 */
static int hf_fix_ExchangeForPhysical = -1; /* Tag 411 */
static int hf_fix_OutMainCntryUIndex = -1; /* Tag 412 */
static int hf_fix_CrossPercent = -1; /* Tag 413 */
static int hf_fix_ProgRptReqs = -1; /* Tag 414 */
static int hf_fix_ProgPeriodInterval = -1; /* Tag 415 */
static int hf_fix_IncTaxInd = -1; /* Tag 416 */
static int hf_fix_NumBidders = -1; /* Tag 417 */
static int hf_fix_TradeType = -1; /* Tag 418 */
static int hf_fix_BasisPxType = -1; /* Tag 419 */
static int hf_fix_NoBidComponents = -1; /* Tag 420 */
static int hf_fix_Country = -1; /* Tag 421 */
static int hf_fix_TotNoStrikes = -1; /* Tag 422 */
static int hf_fix_PriceType = -1; /* Tag 423 */
static int hf_fix_DayOrderQty = -1; /* Tag 424 */
static int hf_fix_DayCumQty = -1; /* Tag 425 */
static int hf_fix_DayAvgPx = -1; /* Tag 426 */
static int hf_fix_GTBookingInst = -1; /* Tag 427 */
static int hf_fix_NoStrikes = -1; /* Tag 428 */
static int hf_fix_ListStatusType = -1; /* Tag 429 */
static int hf_fix_NetGrossInd = -1; /* Tag 430 */
static int hf_fix_ListOrderStatus = -1; /* Tag 431 */
static int hf_fix_ExpireDate = -1; /* Tag 432 */
static int hf_fix_ListExecInstType = -1; /* Tag 433 */
static int hf_fix_CxlRejResponseTo = -1; /* Tag 434 */
static int hf_fix_UnderlyingCouponRate = -1; /* Tag 435 */
static int hf_fix_UnderlyingContractMultiplier = -1; /* Tag 436 */
static int hf_fix_ContraTradeQty = -1; /* Tag 437 */
static int hf_fix_ContraTradeTime = -1; /* Tag 438 */
static int hf_fix_ClearingFirm = -1; /* Tag 439 */
static int hf_fix_ClearingAccount = -1; /* Tag 440 */
static int hf_fix_LiquidityNumSecurities = -1; /* Tag 441 */
static int hf_fix_MultiLegReportingType = -1; /* Tag 442 */
static int hf_fix_StrikeTime = -1; /* Tag 443 */
static int hf_fix_ListStatusText = -1; /* Tag 444 */
static int hf_fix_EncodedListStatusTextLen = -1; /* Tag 445 */
static int hf_fix_EncodedListStatusText = -1; /* Tag 446 */
static int hf_fix_PartyIDSource = -1; /* Tag 447 */
static int hf_fix_PartyID = -1; /* Tag 448 */
static int hf_fix_TotalVolumeTradedDate = -1; /* Tag 449 */
static int hf_fix_TotalVolumeTradedTime = -1; /* Tag 450 */
static int hf_fix_NetChgPrevDay = -1; /* Tag 451 */
static int hf_fix_PartyRole = -1; /* Tag 452 */
static int hf_fix_NoPartyIDs = -1; /* Tag 453 */
static int hf_fix_NoSecurityAltID = -1; /* Tag 454 */
static int hf_fix_SecurityAltID = -1; /* Tag 455 */
static int hf_fix_SecurityAltIDSource = -1; /* Tag 456 */
static int hf_fix_NoUnderlyingSecurityAltID = -1; /* Tag 457 */
static int hf_fix_UnderlyingSecurityAltID = -1; /* Tag 458 */
static int hf_fix_UnderlyingSecurityAltIDSource = -1; /* Tag 459 */
static int hf_fix_Product = -1; /* Tag 460 */
static int hf_fix_CFICode = -1; /* Tag 461 */
static int hf_fix_UnderlyingProduct = -1; /* Tag 462 */
static int hf_fix_UnderlyingCFICode = -1; /* Tag 463 */
static int hf_fix_TestMessageIndicator = -1; /* Tag 464 */
static int hf_fix_QuantityType = -1; /* Tag 465 */
static int hf_fix_BookingRefID = -1; /* Tag 466 */
static int hf_fix_IndividualAllocID = -1; /* Tag 467 */
static int hf_fix_RoundingDirection = -1; /* Tag 468 */
static int hf_fix_RoundingModulus = -1; /* Tag 469 */
static int hf_fix_CountryOfIssue = -1; /* Tag 470 */
static int hf_fix_StateOrProvinceOfIssue = -1; /* Tag 471 */
static int hf_fix_LocaleOfIssue = -1; /* Tag 472 */
static int hf_fix_NoRegistDtls = -1; /* Tag 473 */
static int hf_fix_MailingDtls = -1; /* Tag 474 */
static int hf_fix_InvestorCountryOfResidence = -1; /* Tag 475 */
static int hf_fix_PaymentRef = -1; /* Tag 476 */
static int hf_fix_DistribPaymentMethod = -1; /* Tag 477 */
static int hf_fix_CashDistribCurr = -1; /* Tag 478 */
static int hf_fix_CommCurrency = -1; /* Tag 479 */
static int hf_fix_CancellationRights = -1; /* Tag 480 */
static int hf_fix_MoneyLaunderingStatus = -1; /* Tag 481 */
static int hf_fix_MailingInst = -1; /* Tag 482 */
static int hf_fix_TransBkdTime = -1; /* Tag 483 */
static int hf_fix_ExecPriceType = -1; /* Tag 484 */
static int hf_fix_ExecPriceAdjustment = -1; /* Tag 485 */
static int hf_fix_DateOfBirth = -1; /* Tag 486 */
static int hf_fix_TradeReportTransType = -1; /* Tag 487 */
static int hf_fix_CardHolderName = -1; /* Tag 488 */
static int hf_fix_CardNumber = -1; /* Tag 489 */
static int hf_fix_CardExpDate = -1; /* Tag 490 */
static int hf_fix_CardIssNo = -1; /* Tag 491 */
static int hf_fix_PaymentMethod = -1; /* Tag 492 */
static int hf_fix_RegistAcctType = -1; /* Tag 493 */
static int hf_fix_Designation = -1; /* Tag 494 */
static int hf_fix_TaxAdvantageType = -1; /* Tag 495 */
static int hf_fix_RegistRejReasonText = -1; /* Tag 496 */
static int hf_fix_FundRenewWaiv = -1; /* Tag 497 */
static int hf_fix_CashDistribAgentName = -1; /* Tag 498 */
static int hf_fix_CashDistribAgentCode = -1; /* Tag 499 */
static int hf_fix_CashDistribAgentAcctNumber = -1; /* Tag 500 */
static int hf_fix_CashDistribPayRef = -1; /* Tag 501 */
static int hf_fix_CashDistribAgentAcctName = -1; /* Tag 502 */
static int hf_fix_CardStartDate = -1; /* Tag 503 */
static int hf_fix_PaymentDate = -1; /* Tag 504 */
static int hf_fix_PaymentRemitterID = -1; /* Tag 505 */
static int hf_fix_RegistStatus = -1; /* Tag 506 */
static int hf_fix_RegistRejReasonCode = -1; /* Tag 507 */
static int hf_fix_RegistRefID = -1; /* Tag 508 */
static int hf_fix_RegistDetls = -1; /* Tag 509 */
static int hf_fix_NoDistribInsts = -1; /* Tag 510 */
static int hf_fix_RegistEmail = -1; /* Tag 511 */
static int hf_fix_DistribPercentage = -1; /* Tag 512 */
static int hf_fix_RegistID = -1; /* Tag 513 */
static int hf_fix_RegistTransType = -1; /* Tag 514 */
static int hf_fix_ExecValuationPoint = -1; /* Tag 515 */
static int hf_fix_OrderPercent = -1; /* Tag 516 */
static int hf_fix_OwnershipType = -1; /* Tag 517 */
static int hf_fix_NoContAmts = -1; /* Tag 518 */
static int hf_fix_ContAmtType = -1; /* Tag 519 */
static int hf_fix_ContAmtValue = -1; /* Tag 520 */
static int hf_fix_ContAmtCurr = -1; /* Tag 521 */
static int hf_fix_OwnerType = -1; /* Tag 522 */
static int hf_fix_PartySubID = -1; /* Tag 523 */
static int hf_fix_NestedPartyID = -1; /* Tag 524 */
static int hf_fix_NestedPartyIDSource = -1; /* Tag 525 */
static int hf_fix_SecondaryClOrdID = -1; /* Tag 526 */
static int hf_fix_SecondaryExecID = -1; /* Tag 527 */
static int hf_fix_OrderCapacity = -1; /* Tag 528 */
static int hf_fix_OrderRestrictions = -1; /* Tag 529 */
static int hf_fix_MassCancelRequestType = -1; /* Tag 530 */
static int hf_fix_MassCancelResponse = -1; /* Tag 531 */
static int hf_fix_MassCancelRejectReason = -1; /* Tag 532 */
static int hf_fix_TotalAffectedOrders = -1; /* Tag 533 */
static int hf_fix_NoAffectedOrders = -1; /* Tag 534 */
static int hf_fix_AffectedOrderID = -1; /* Tag 535 */
static int hf_fix_AffectedSecondaryOrderID = -1; /* Tag 536 */
static int hf_fix_QuoteType = -1; /* Tag 537 */
static int hf_fix_NestedPartyRole = -1; /* Tag 538 */
static int hf_fix_NoNestedPartyIDs = -1; /* Tag 539 */
static int hf_fix_TotalAccruedInterestAmt = -1; /* Tag 540 */
static int hf_fix_MaturityDate = -1; /* Tag 541 */
static int hf_fix_UnderlyingMaturityDate = -1; /* Tag 542 */
static int hf_fix_InstrRegistry = -1; /* Tag 543 */
static int hf_fix_CashMargin = -1; /* Tag 544 */
static int hf_fix_NestedPartySubID = -1; /* Tag 545 */
static int hf_fix_Scope = -1; /* Tag 546 */
static int hf_fix_MDImplicitDelete = -1; /* Tag 547 */
static int hf_fix_CrossID = -1; /* Tag 548 */
static int hf_fix_CrossType = -1; /* Tag 549 */
static int hf_fix_CrossPrioritization = -1; /* Tag 550 */
static int hf_fix_OrigCrossID = -1; /* Tag 551 */
static int hf_fix_NoSides = -1; /* Tag 552 */
static int hf_fix_Username = -1; /* Tag 553 */
static int hf_fix_Password = -1; /* Tag 554 */
static int hf_fix_NoLegs = -1; /* Tag 555 */
static int hf_fix_LegCurrency = -1; /* Tag 556 */
static int hf_fix_TotalNumSecurityTypes = -1; /* Tag 557 */
static int hf_fix_NoSecurityTypes = -1; /* Tag 558 */
static int hf_fix_SecurityListRequestType = -1; /* Tag 559 */
static int hf_fix_SecurityRequestResult = -1; /* Tag 560 */
static int hf_fix_RoundLot = -1; /* Tag 561 */
static int hf_fix_MinTradeVol = -1; /* Tag 562 */
static int hf_fix_MultiLegRptTypeReq = -1; /* Tag 563 */
static int hf_fix_LegPositionEffect = -1; /* Tag 564 */
static int hf_fix_LegCoveredOrUncovered = -1; /* Tag 565 */
static int hf_fix_LegPrice = -1; /* Tag 566 */
static int hf_fix_TradSesStatusRejReason = -1; /* Tag 567 */
static int hf_fix_TradeRequestID = -1; /* Tag 568 */
static int hf_fix_TradeRequestType = -1; /* Tag 569 */
static int hf_fix_PreviouslyReported = -1; /* Tag 570 */
static int hf_fix_TradeReportID = -1; /* Tag 571 */
static int hf_fix_TradeReportRefID = -1; /* Tag 572 */
static int hf_fix_MatchStatus = -1; /* Tag 573 */
static int hf_fix_MatchType = -1; /* Tag 574 */
static int hf_fix_OddLot = -1; /* Tag 575 */
static int hf_fix_NoClearingInstructions = -1; /* Tag 576 */
static int hf_fix_ClearingInstruction = -1; /* Tag 577 */
static int hf_fix_TradeInputSource = -1; /* Tag 578 */
static int hf_fix_TradeInputDevice = -1; /* Tag 579 */
static int hf_fix_NoDates = -1; /* Tag 580 */
static int hf_fix_AccountType = -1; /* Tag 581 */
static int hf_fix_CustOrderCapacity = -1; /* Tag 582 */
static int hf_fix_ClOrdLinkID = -1; /* Tag 583 */
static int hf_fix_MassStatusReqID = -1; /* Tag 584 */
static int hf_fix_MassStatusReqType = -1; /* Tag 585 */
static int hf_fix_OrigOrdModTime = -1; /* Tag 586 */
static int hf_fix_LegSettlmntTyp = -1; /* Tag 587 */
static int hf_fix_LegFutSettDate = -1; /* Tag 588 */
static int hf_fix_DayBookingInst = -1; /* Tag 589 */
static int hf_fix_BookingUnit = -1; /* Tag 590 */
static int hf_fix_PreallocMethod = -1; /* Tag 591 */
static int hf_fix_UnderlyingCountryOfIssue = -1; /* Tag 592 */
static int hf_fix_UnderlyingStateOrProvinceOfIssue = -1; /* Tag 593 */
static int hf_fix_UnderlyingLocaleOfIssue = -1; /* Tag 594 */
static int hf_fix_UnderlyingInstrRegistry = -1; /* Tag 595 */
static int hf_fix_LegCountryOfIssue = -1; /* Tag 596 */
static int hf_fix_LegStateOrProvinceOfIssue = -1; /* Tag 597 */
static int hf_fix_LegLocaleOfIssue = -1; /* Tag 598 */
static int hf_fix_LegInstrRegistry = -1; /* Tag 599 */
static int hf_fix_LegSymbol = -1; /* Tag 600 */
static int hf_fix_LegSymbolSfx = -1; /* Tag 601 */
static int hf_fix_LegSecurityID = -1; /* Tag 602 */
static int hf_fix_LegSecurityIDSource = -1; /* Tag 603 */
static int hf_fix_NoLegSecurityAltID = -1; /* Tag 604 */
static int hf_fix_LegSecurityAltID = -1; /* Tag 605 */
static int hf_fix_LegSecurityAltIDSource = -1; /* Tag 606 */
static int hf_fix_LegProduct = -1; /* Tag 607 */
static int hf_fix_LegCFICode = -1; /* Tag 608 */
static int hf_fix_LegSecurityType = -1; /* Tag 609 */
static int hf_fix_LegMaturityMonthYear = -1; /* Tag 610 */
static int hf_fix_LegMaturityDate = -1; /* Tag 611 */
static int hf_fix_LegStrikePrice = -1; /* Tag 612 */
static int hf_fix_LegOptAttribute = -1; /* Tag 613 */
static int hf_fix_LegContractMultiplier = -1; /* Tag 614 */
static int hf_fix_LegCouponRate = -1; /* Tag 615 */
static int hf_fix_LegSecurityExchange = -1; /* Tag 616 */
static int hf_fix_LegIssuer = -1; /* Tag 617 */
static int hf_fix_EncodedLegIssuerLen = -1; /* Tag 618 */
static int hf_fix_EncodedLegIssuer = -1; /* Tag 619 */
static int hf_fix_LegSecurityDesc = -1; /* Tag 620 */
static int hf_fix_EncodedLegSecurityDescLen = -1; /* Tag 621 */
static int hf_fix_EncodedLegSecurityDesc = -1; /* Tag 622 */
static int hf_fix_LegRatioQty = -1; /* Tag 623 */
static int hf_fix_LegSide = -1; /* Tag 624 */
static int hf_fix_TradingSessionSubID = -1; /* Tag 625 */
static int hf_fix_AllocType = -1; /* Tag 626 */
static int hf_fix_NoHops = -1; /* Tag 627 */
static int hf_fix_HopCompID = -1; /* Tag 628 */
static int hf_fix_HopSendingTime = -1; /* Tag 629 */
static int hf_fix_HopRefID = -1; /* Tag 630 */
static int hf_fix_MidPx = -1; /* Tag 631 */
static int hf_fix_BidYield = -1; /* Tag 632 */
static int hf_fix_MidYield = -1; /* Tag 633 */
static int hf_fix_OfferYield = -1; /* Tag 634 */
static int hf_fix_ClearingFeeIndicator = -1; /* Tag 635 */
static int hf_fix_WorkingIndicator = -1; /* Tag 636 */
static int hf_fix_LegLastPx = -1; /* Tag 637 */
static int hf_fix_PriorityIndicator = -1; /* Tag 638 */
static int hf_fix_PriceImprovement = -1; /* Tag 639 */
static int hf_fix_Price2 = -1; /* Tag 640 */
static int hf_fix_LastForwardPoints2 = -1; /* Tag 641 */
static int hf_fix_BidForwardPoints2 = -1; /* Tag 642 */
static int hf_fix_OfferForwardPoints2 = -1; /* Tag 643 */
static int hf_fix_RFQReqID = -1; /* Tag 644 */
static int hf_fix_MktBidPx = -1; /* Tag 645 */
static int hf_fix_MktOfferPx = -1; /* Tag 646 */
static int hf_fix_MinBidSize = -1; /* Tag 647 */
static int hf_fix_MinOfferSize = -1; /* Tag 648 */
static int hf_fix_QuoteStatusReqID = -1; /* Tag 649 */
static int hf_fix_LegalConfirm = -1; /* Tag 650 */
static int hf_fix_UnderlyingLastPx = -1; /* Tag 651 */
static int hf_fix_UnderlyingLastQty = -1; /* Tag 652 */
static int hf_fix_SecDefStatus = -1; /* Tag 653 */
static int hf_fix_LegRefID = -1; /* Tag 654 */
static int hf_fix_ContraLegRefID = -1; /* Tag 655 */
static int hf_fix_SettlCurrBidFxRate = -1; /* Tag 656 */
static int hf_fix_SettlCurrOfferFxRate = -1; /* Tag 657 */
static int hf_fix_QuoteRequestRejectReason = -1; /* Tag 658 */
static int hf_fix_SideComplianceID = -1; /* Tag 659 */

static void dissect_fix_init(void) {
    g_datalist_clear(&msg_types);

    g_datalist_init(&msg_types);

    g_datalist_set_data(&msg_types, "0", "Heartbeat");
    g_datalist_set_data(&msg_types, "1", "Test Request");
    g_datalist_set_data(&msg_types, "2", "Resend Request");
    g_datalist_set_data(&msg_types, "3", "Reject");
    g_datalist_set_data(&msg_types, "4", "Sequence Reset");
    g_datalist_set_data(&msg_types, "5", "Logout");
    g_datalist_set_data(&msg_types, "6", "Indication of Interest");
    g_datalist_set_data(&msg_types, "7", "Advertisement");
    g_datalist_set_data(&msg_types, "8", "Execution Report");
    g_datalist_set_data(&msg_types, "9", "Order Cancel Reject");
    g_datalist_set_data(&msg_types, "A", "Logon");
    g_datalist_set_data(&msg_types, "B", "News");
    g_datalist_set_data(&msg_types, "C", "Email");
    g_datalist_set_data(&msg_types, "D", "Order - Single");
    g_datalist_set_data(&msg_types, "E", "Order - List");
    g_datalist_set_data(&msg_types, "F", "Order Cancel Request");
    g_datalist_set_data(&msg_types, "G", "Order Cancel - Replace Request");
    g_datalist_set_data(&msg_types, "H", "Order Status Request");
    g_datalist_set_data(&msg_types, "J", "Allocation");
    g_datalist_set_data(&msg_types, "K", "List Cancel Request");
    g_datalist_set_data(&msg_types, "L", "List Execute");
    g_datalist_set_data(&msg_types, "M", "List Status Request");
    g_datalist_set_data(&msg_types, "N", "List Status");
    g_datalist_set_data(&msg_types, "P", "Allocation ACK");
    g_datalist_set_data(&msg_types, "Q", "Don't Know Trade (DK)");
    g_datalist_set_data(&msg_types, "R", "Quote Request");
    g_datalist_set_data(&msg_types, "S", "Quote");
    g_datalist_set_data(&msg_types, "T", "Settlement Instructions");
    g_datalist_set_data(&msg_types, "V", "Market Data Request");
    g_datalist_set_data(&msg_types, "W", "Market Data-Snapshot - Full Refresh");
    g_datalist_set_data(&msg_types, "X", "Market Data-Incremental Refresh");
    g_datalist_set_data(&msg_types, "Y", "Market Data Request Reject");
    g_datalist_set_data(&msg_types, "Z", "Quote Cancel");
    g_datalist_set_data(&msg_types, "a", "Quote Status Request");
    g_datalist_set_data(&msg_types, "b", "Mass Quote Acknowledgement");
    g_datalist_set_data(&msg_types, "c", "Security Definition Request");
    g_datalist_set_data(&msg_types, "d", "Security Definition");
    g_datalist_set_data(&msg_types, "e", "Security Status Request");
    g_datalist_set_data(&msg_types, "f", "Security Status");
    g_datalist_set_data(&msg_types, "g", "Trading Session Status Request");
    g_datalist_set_data(&msg_types, "h", "Trading Session Status");
    g_datalist_set_data(&msg_types, "i", "Mass Quote");
    g_datalist_set_data(&msg_types, "j", "Business Message Reject");
    g_datalist_set_data(&msg_types, "k", "Bid Request ");
    g_datalist_set_data(&msg_types, "l", "Bid Response");
    g_datalist_set_data(&msg_types, "m", "List Strike Price");
    g_datalist_set_data(&msg_types, "n", "XML message");
    g_datalist_set_data(&msg_types, "o", "Registration Instructions");
    g_datalist_set_data(&msg_types, "p", "Registration Instructions Response");
    g_datalist_set_data(&msg_types, "q", "Order Mass Cancel Request");
    g_datalist_set_data(&msg_types, "r", "Order Mass Cancel Report");
    g_datalist_set_data(&msg_types, "s", "New Order - Cross");
    g_datalist_set_data(&msg_types, "t", "Cross Order Cancel - Replace Request");
    g_datalist_set_data(&msg_types, "u", "Cross Order Cancel Request");
    g_datalist_set_data(&msg_types, "v", "Security Type Request");
    g_datalist_set_data(&msg_types, "w", "Security Types");
    g_datalist_set_data(&msg_types, "x", "Security List Request");
    g_datalist_set_data(&msg_types, "y", "Security List");
    g_datalist_set_data(&msg_types, "z", "Derivative Security List Request");
    g_datalist_set_data(&msg_types, "AA", "Derivative Security List");
    g_datalist_set_data(&msg_types, "AB", "New Order - Multileg");
    g_datalist_set_data(&msg_types, "AC", "Multileg Order Cancel - Replace");
    g_datalist_set_data(&msg_types, "AD", "Trade Capture Report Request");
    g_datalist_set_data(&msg_types, "AE", "Trade Capture Report");
    g_datalist_set_data(&msg_types, "AF", "Order Mass Status Request");
    g_datalist_set_data(&msg_types, "AG", "Quote Request Reject");
    g_datalist_set_data(&msg_types, "AH", "RFQ Request");
    g_datalist_set_data(&msg_types, "AI", "Quote Status Report");

}

/* Code to actually dissect the packets */
static gboolean
dissect_fix(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *fix_tree;

    gint next;
    int linelen;
    int offset = 0;
    int field_offset, value_offset, ctrla_offset, equals;
    int tag;
    char *value;
    char *tag_str;
    int field_len = 0;
    int tag_len = 0;
    int value_len = 0;

    /* get at least the fix version: 8=FIX.x.x */
    if (tvb_strneql(tvb, 0, "8=FIX.", 6) != 0) {
        /* not a fix packet */
        return FALSE;
    }

    linelen = tvb_find_line_end(tvb, 0, -1, &next, 0);

    /* begin string */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        return FALSE;
    }
    offset = ctrla_offset + 1;

    /* msg length */
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        return FALSE;
    }
    offset = ctrla_offset + 1;

    /* msg type */
    field_offset = offset;
    ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
    if (ctrla_offset == -1) {
        return FALSE;
    }

    field_len = ctrla_offset - field_offset + 1;
    equals = tvb_find_guint8(tvb, offset, field_len, '=');
    if (equals == -1) {
        return FALSE;
    }

    value_offset = equals + 1;
    value_len = ctrla_offset - value_offset;
    if (value_len < 1) {
        return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FIX");
    }
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        char *msg_type;

        value = tvb_get_ephemeral_string(tvb, value_offset, value_len);
        msg_type = (char *)g_datalist_get_data(&msg_types, value);
        if(msg_type) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", msg_type);
        }
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree) {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_fix, tvb, 0, -1, FALSE);
        fix_tree = proto_item_add_subtree(ti, ett_fix);

        field_offset = offset = 0;
        ctrla_offset = tvb_find_guint8(tvb, offset, -1, 0x01);
        if (ctrla_offset == -1) {
            /* XXX - put an error indication here.  It's too late
               to return FALSE; we've already started dissecting,
               and if a heuristic dissector starts dissecting
               (either updating the columns or creating a protocol
               tree) and then gives up, it leaves crud behind that
               messes up other dissectors that might process the
               packet. */
            return TRUE;
        }

        while(ctrla_offset != -1 && offset < linelen) {
            field_len = ctrla_offset - field_offset + 1;
            if(offset >= linelen) {
                break;
            }

            equals = tvb_find_guint8(tvb, offset, field_len, '=');
            if (equals == -1) {
                /* XXX - put an error indication here.  It's too late
                   to return FALSE; we've already started dissecting,
                   and if a heuristic dissector starts dissecting
                   (either updating the columns or creating a protocol
                   tree) and then gives up, it leaves crud behind that
                   messes up other dissectors that might process the
                   packet. */
                return TRUE;
            }

            value_offset = equals + 1;
            value_len = ctrla_offset - value_offset;

            tag_len = equals - field_offset;
            if (tag_len < 1 || value_len < 1) {
                /* XXX - put an error indication here.  It's too late
                   to return FALSE; we've already started dissecting,
                   and if a heuristic dissector starts dissecting
                   (either updating the columns or creating a protocol
                   tree) and then gives up, it leaves crud behind that
                   messes up other dissectors that might process the
                   packet. */
                return TRUE;
            }
            tag_str = tvb_get_ephemeral_string(tvb, field_offset, tag_len);
            tag = atoi(tag_str);

            value = tvb_get_ephemeral_string(tvb, value_offset, value_len);

            switch(tag) {
                case 1: /* Field Account */
                    proto_tree_add_string(fix_tree, hf_fix_Account, tvb, offset, field_len, value);
                    break;
                case 2: /* Field AdvId */
                    proto_tree_add_string(fix_tree, hf_fix_AdvId, tvb, offset, field_len, value);
                    break;
                case 3: /* Field AdvRefID */
                    proto_tree_add_string(fix_tree, hf_fix_AdvRefID, tvb, offset, field_len, value);
                    break;
                case 4: /* Field AdvSide */
                    proto_tree_add_string(fix_tree, hf_fix_AdvSide, tvb, offset, field_len, value);
                    break;
                case 5: /* Field AdvTransType */
                    proto_tree_add_string(fix_tree, hf_fix_AdvTransType, tvb, offset, field_len, value);
                    break;
                case 6: /* Field AvgPx */
                    proto_tree_add_string(fix_tree, hf_fix_AvgPx, tvb, offset, field_len, value);
                    break;
                case 7: /* Field BeginSeqNo */
                    proto_tree_add_string(fix_tree, hf_fix_BeginSeqNo, tvb, offset, field_len, value);
                    break;
                case 8: /* Field BeginString */
                    proto_tree_add_string(fix_tree, hf_fix_BeginString, tvb, offset, field_len, value);
                    break;
                case 9: /* Field BodyLength */
                    proto_tree_add_string(fix_tree, hf_fix_BodyLength, tvb, offset, field_len, value);
                    break;
                case 10: /* Field CheckSum */
                    proto_tree_add_string(fix_tree, hf_fix_CheckSum, tvb, offset, field_len, value);
                    break;
                case 11: /* Field ClOrdID */
                    proto_tree_add_string(fix_tree, hf_fix_ClOrdID, tvb, offset, field_len, value);
                    break;
                case 12: /* Field Commission */
                    proto_tree_add_string(fix_tree, hf_fix_Commission, tvb, offset, field_len, value);
                    break;
                case 13: /* Field CommType */
                    proto_tree_add_string(fix_tree, hf_fix_CommType, tvb, offset, field_len, value);
                    break;
                case 14: /* Field CumQty */
                    proto_tree_add_string(fix_tree, hf_fix_CumQty, tvb, offset, field_len, value);
                    break;
                case 15: /* Field Currency */
                    proto_tree_add_string(fix_tree, hf_fix_Currency, tvb, offset, field_len, value);
                    break;
                case 16: /* Field EndSeqNo */
                    proto_tree_add_string(fix_tree, hf_fix_EndSeqNo, tvb, offset, field_len, value);
                    break;
                case 17: /* Field ExecID */
                    proto_tree_add_string(fix_tree, hf_fix_ExecID, tvb, offset, field_len, value);
                    break;
                case 18: /* Field ExecInst */
                    proto_tree_add_string(fix_tree, hf_fix_ExecInst, tvb, offset, field_len, value);
                    break;
                case 19: /* Field ExecRefID */
                    proto_tree_add_string(fix_tree, hf_fix_ExecRefID, tvb, offset, field_len, value);
                    break;
                case 20: /* Field ExecTransType */
                    proto_tree_add_string(fix_tree, hf_fix_ExecTransType, tvb, offset, field_len, value);
                    break;
                case 21: /* Field HandlInst */
                    proto_tree_add_string(fix_tree, hf_fix_HandlInst, tvb, offset, field_len, value);
                    break;
                case 22: /* Field SecurityIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityIDSource, tvb, offset, field_len, value);
                    break;
                case 23: /* Field IOIid */
                    proto_tree_add_string(fix_tree, hf_fix_IOIid, tvb, offset, field_len, value);
                    break;
                case 24: /* Field IOIOthSvc */
                    proto_tree_add_string(fix_tree, hf_fix_IOIOthSvc, tvb, offset, field_len, value);
                    break;
                case 25: /* Field IOIQltyInd */
                    proto_tree_add_string(fix_tree, hf_fix_IOIQltyInd, tvb, offset, field_len, value);
                    break;
                case 26: /* Field IOIRefID */
                    proto_tree_add_string(fix_tree, hf_fix_IOIRefID, tvb, offset, field_len, value);
                    break;
                case 27: /* Field IOIQty */
                    proto_tree_add_string(fix_tree, hf_fix_IOIQty, tvb, offset, field_len, value);
                    break;
                case 28: /* Field IOITransType */
                    proto_tree_add_string(fix_tree, hf_fix_IOITransType, tvb, offset, field_len, value);
                    break;
                case 29: /* Field LastCapacity */
                    proto_tree_add_string(fix_tree, hf_fix_LastCapacity, tvb, offset, field_len, value);
                    break;
                case 30: /* Field LastMkt */
                    proto_tree_add_string(fix_tree, hf_fix_LastMkt, tvb, offset, field_len, value);
                    break;
                case 31: /* Field LastPx */
                    proto_tree_add_string(fix_tree, hf_fix_LastPx, tvb, offset, field_len, value);
                    break;
                case 32: /* Field LastQty */
                    proto_tree_add_string(fix_tree, hf_fix_LastQty, tvb, offset, field_len, value);
                    break;
                case 33: /* Field LinesOfText */
                    proto_tree_add_string(fix_tree, hf_fix_LinesOfText, tvb, offset, field_len, value);
                    break;
                case 34: /* Field MsgSeqNum */
                    proto_tree_add_string(fix_tree, hf_fix_MsgSeqNum, tvb, offset, field_len, value);
                    break;
                case 35: /* Field MsgType */
                    proto_tree_add_string(fix_tree, hf_fix_MsgType, tvb, offset, field_len, value);
                    break;
                case 36: /* Field NewSeqNo */
                    proto_tree_add_string(fix_tree, hf_fix_NewSeqNo, tvb, offset, field_len, value);
                    break;
                case 37: /* Field OrderID */
                    proto_tree_add_string(fix_tree, hf_fix_OrderID, tvb, offset, field_len, value);
                    break;
                case 38: /* Field OrderQty */
                    proto_tree_add_string(fix_tree, hf_fix_OrderQty, tvb, offset, field_len, value);
                    break;
                case 39: /* Field OrdStatus */
                    proto_tree_add_string(fix_tree, hf_fix_OrdStatus, tvb, offset, field_len, value);
                    break;
                case 40: /* Field OrdType */
                    proto_tree_add_string(fix_tree, hf_fix_OrdType, tvb, offset, field_len, value);
                    break;
                case 41: /* Field OrigClOrdID */
                    proto_tree_add_string(fix_tree, hf_fix_OrigClOrdID, tvb, offset, field_len, value);
                    break;
                case 42: /* Field OrigTime */
                    proto_tree_add_string(fix_tree, hf_fix_OrigTime, tvb, offset, field_len, value);
                    break;
                case 43: /* Field PossDupFlag */
                    proto_tree_add_string(fix_tree, hf_fix_PossDupFlag, tvb, offset, field_len, value);
                    break;
                case 44: /* Field Price */
                    proto_tree_add_string(fix_tree, hf_fix_Price, tvb, offset, field_len, value);
                    break;
                case 45: /* Field RefSeqNum */
                    proto_tree_add_string(fix_tree, hf_fix_RefSeqNum, tvb, offset, field_len, value);
                    break;
                case 46: /* Field RelatdSym */
                    proto_tree_add_string(fix_tree, hf_fix_RelatdSym, tvb, offset, field_len, value);
                    break;
                case 47: /* Field Rule80A */
                    proto_tree_add_string(fix_tree, hf_fix_Rule80A, tvb, offset, field_len, value);
                    break;
                case 48: /* Field SecurityID */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityID, tvb, offset, field_len, value);
                    break;
                case 49: /* Field SenderCompID */
                    proto_tree_add_string(fix_tree, hf_fix_SenderCompID, tvb, offset, field_len, value);
                    break;
                case 50: /* Field SenderSubID */
                    proto_tree_add_string(fix_tree, hf_fix_SenderSubID, tvb, offset, field_len, value);
                    break;
                case 51: /* Field SendingDate */
                    proto_tree_add_string(fix_tree, hf_fix_SendingDate, tvb, offset, field_len, value);
                    break;
                case 52: /* Field SendingTime */
                    proto_tree_add_string(fix_tree, hf_fix_SendingTime, tvb, offset, field_len, value);
                    break;
                case 53: /* Field Quantity */
                    proto_tree_add_string(fix_tree, hf_fix_Quantity, tvb, offset, field_len, value);
                    break;
                case 54: /* Field Side */
                    proto_tree_add_string(fix_tree, hf_fix_Side, tvb, offset, field_len, value);
                    break;
                case 55: /* Field Symbol */
                    proto_tree_add_string(fix_tree, hf_fix_Symbol, tvb, offset, field_len, value);
                    break;
                case 56: /* Field TargetCompID */
                    proto_tree_add_string(fix_tree, hf_fix_TargetCompID, tvb, offset, field_len, value);
                    break;
                case 57: /* Field TargetSubID */
                    proto_tree_add_string(fix_tree, hf_fix_TargetSubID, tvb, offset, field_len, value);
                    break;
                case 58: /* Field Text */
                    proto_tree_add_string(fix_tree, hf_fix_Text, tvb, offset, field_len, value);
                    break;
                case 59: /* Field TimeInForce */
                    proto_tree_add_string(fix_tree, hf_fix_TimeInForce, tvb, offset, field_len, value);
                    break;
                case 60: /* Field TransactTime */
                    proto_tree_add_string(fix_tree, hf_fix_TransactTime, tvb, offset, field_len, value);
                    break;
                case 61: /* Field Urgency */
                    proto_tree_add_string(fix_tree, hf_fix_Urgency, tvb, offset, field_len, value);
                    break;
                case 62: /* Field ValidUntilTime */
                    proto_tree_add_string(fix_tree, hf_fix_ValidUntilTime, tvb, offset, field_len, value);
                    break;
                case 63: /* Field SettlmntTyp */
                    proto_tree_add_string(fix_tree, hf_fix_SettlmntTyp, tvb, offset, field_len, value);
                    break;
                case 64: /* Field FutSettDate */
                    proto_tree_add_string(fix_tree, hf_fix_FutSettDate, tvb, offset, field_len, value);
                    break;
                case 65: /* Field SymbolSfx */
                    proto_tree_add_string(fix_tree, hf_fix_SymbolSfx, tvb, offset, field_len, value);
                    break;
                case 66: /* Field ListID */
                    proto_tree_add_string(fix_tree, hf_fix_ListID, tvb, offset, field_len, value);
                    break;
                case 67: /* Field ListSeqNo */
                    proto_tree_add_string(fix_tree, hf_fix_ListSeqNo, tvb, offset, field_len, value);
                    break;
                case 68: /* Field TotNoOrders */
                    proto_tree_add_string(fix_tree, hf_fix_TotNoOrders, tvb, offset, field_len, value);
                    break;
                case 69: /* Field ListExecInst */
                    proto_tree_add_string(fix_tree, hf_fix_ListExecInst, tvb, offset, field_len, value);
                    break;
                case 70: /* Field AllocID */
                    proto_tree_add_string(fix_tree, hf_fix_AllocID, tvb, offset, field_len, value);
                    break;
                case 71: /* Field AllocTransType */
                    proto_tree_add_string(fix_tree, hf_fix_AllocTransType, tvb, offset, field_len, value);
                    break;
                case 72: /* Field RefAllocID */
                    proto_tree_add_string(fix_tree, hf_fix_RefAllocID, tvb, offset, field_len, value);
                    break;
                case 73: /* Field NoOrders */
                    proto_tree_add_string(fix_tree, hf_fix_NoOrders, tvb, offset, field_len, value);
                    break;
                case 74: /* Field AvgPrxPrecision */
                    proto_tree_add_string(fix_tree, hf_fix_AvgPrxPrecision, tvb, offset, field_len, value);
                    break;
                case 75: /* Field TradeDate */
                    proto_tree_add_string(fix_tree, hf_fix_TradeDate, tvb, offset, field_len, value);
                    break;
                case 76: /* Field ExecBroker */
                    proto_tree_add_string(fix_tree, hf_fix_ExecBroker, tvb, offset, field_len, value);
                    break;
                case 77: /* Field PositionEffect */
                    proto_tree_add_string(fix_tree, hf_fix_PositionEffect, tvb, offset, field_len, value);
                    break;
                case 78: /* Field NoAllocs */
                    proto_tree_add_string(fix_tree, hf_fix_NoAllocs, tvb, offset, field_len, value);
                    break;
                case 79: /* Field AllocAccount */
                    proto_tree_add_string(fix_tree, hf_fix_AllocAccount, tvb, offset, field_len, value);
                    break;
                case 80: /* Field AllocQty */
                    proto_tree_add_string(fix_tree, hf_fix_AllocQty, tvb, offset, field_len, value);
                    break;
                case 81: /* Field ProcessCode */
                    proto_tree_add_string(fix_tree, hf_fix_ProcessCode, tvb, offset, field_len, value);
                    break;
                case 82: /* Field NoRpts */
                    proto_tree_add_string(fix_tree, hf_fix_NoRpts, tvb, offset, field_len, value);
                    break;
                case 83: /* Field RptSeq */
                    proto_tree_add_string(fix_tree, hf_fix_RptSeq, tvb, offset, field_len, value);
                    break;
                case 84: /* Field CxlQty */
                    proto_tree_add_string(fix_tree, hf_fix_CxlQty, tvb, offset, field_len, value);
                    break;
                case 85: /* Field NoDlvyInst */
                    proto_tree_add_string(fix_tree, hf_fix_NoDlvyInst, tvb, offset, field_len, value);
                    break;
                case 86: /* Field DlvyInst */
                    proto_tree_add_string(fix_tree, hf_fix_DlvyInst, tvb, offset, field_len, value);
                    break;
                case 87: /* Field AllocStatus */
                    proto_tree_add_string(fix_tree, hf_fix_AllocStatus, tvb, offset, field_len, value);
                    break;
                case 88: /* Field AllocRejCode */
                    proto_tree_add_string(fix_tree, hf_fix_AllocRejCode, tvb, offset, field_len, value);
                    break;
                case 89: /* Field Signature */
                    proto_tree_add_string(fix_tree, hf_fix_Signature, tvb, offset, field_len, value);
                    break;
                case 90: /* Field SecureDataLen */
                    proto_tree_add_string(fix_tree, hf_fix_SecureDataLen, tvb, offset, field_len, value);
                    break;
                case 91: /* Field SecureData */
                    proto_tree_add_string(fix_tree, hf_fix_SecureData, tvb, offset, field_len, value);
                    break;
                case 92: /* Field BrokerOfCredit */
                    proto_tree_add_string(fix_tree, hf_fix_BrokerOfCredit, tvb, offset, field_len, value);
                    break;
                case 93: /* Field SignatureLength */
                    proto_tree_add_string(fix_tree, hf_fix_SignatureLength, tvb, offset, field_len, value);
                    break;
                case 94: /* Field EmailType */
                    proto_tree_add_string(fix_tree, hf_fix_EmailType, tvb, offset, field_len, value);
                    break;
                case 95: /* Field RawDataLength */
                    proto_tree_add_string(fix_tree, hf_fix_RawDataLength, tvb, offset, field_len, value);
                    break;
                case 96: /* Field RawData */
                    proto_tree_add_string(fix_tree, hf_fix_RawData, tvb, offset, field_len, value);
                    break;
                case 97: /* Field PossResend */
                    proto_tree_add_string(fix_tree, hf_fix_PossResend, tvb, offset, field_len, value);
                    break;
                case 98: /* Field EncryptMethod */
                    proto_tree_add_string(fix_tree, hf_fix_EncryptMethod, tvb, offset, field_len, value);
                    break;
                case 99: /* Field StopPx */
                    proto_tree_add_string(fix_tree, hf_fix_StopPx, tvb, offset, field_len, value);
                    break;
                case 100: /* Field ExDestination */
                    proto_tree_add_string(fix_tree, hf_fix_ExDestination, tvb, offset, field_len, value);
                    break;
                case 102: /* Field CxlRejReason */
                    proto_tree_add_string(fix_tree, hf_fix_CxlRejReason, tvb, offset, field_len, value);
                    break;
                case 103: /* Field OrdRejReason */
                    proto_tree_add_string(fix_tree, hf_fix_OrdRejReason, tvb, offset, field_len, value);
                    break;
                case 104: /* Field IOIQualifier */
                    proto_tree_add_string(fix_tree, hf_fix_IOIQualifier, tvb, offset, field_len, value);
                    break;
                case 105: /* Field WaveNo */
                    proto_tree_add_string(fix_tree, hf_fix_WaveNo, tvb, offset, field_len, value);
                    break;
                case 106: /* Field Issuer */
                    proto_tree_add_string(fix_tree, hf_fix_Issuer, tvb, offset, field_len, value);
                    break;
                case 107: /* Field SecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityDesc, tvb, offset, field_len, value);
                    break;
                case 108: /* Field HeartBtInt */
                    proto_tree_add_string(fix_tree, hf_fix_HeartBtInt, tvb, offset, field_len, value);
                    break;
                case 109: /* Field ClientID */
                    proto_tree_add_string(fix_tree, hf_fix_ClientID, tvb, offset, field_len, value);
                    break;
                case 110: /* Field MinQty */
                    proto_tree_add_string(fix_tree, hf_fix_MinQty, tvb, offset, field_len, value);
                    break;
                case 111: /* Field MaxFloor */
                    proto_tree_add_string(fix_tree, hf_fix_MaxFloor, tvb, offset, field_len, value);
                    break;
                case 112: /* Field TestReqID */
                    proto_tree_add_string(fix_tree, hf_fix_TestReqID, tvb, offset, field_len, value);
                    break;
                case 113: /* Field ReportToExch */
                    proto_tree_add_string(fix_tree, hf_fix_ReportToExch, tvb, offset, field_len, value);
                    break;
                case 114: /* Field LocateReqd */
                    proto_tree_add_string(fix_tree, hf_fix_LocateReqd, tvb, offset, field_len, value);
                    break;
                case 115: /* Field OnBehalfOfCompID */
                    proto_tree_add_string(fix_tree, hf_fix_OnBehalfOfCompID, tvb, offset, field_len, value);
                    break;
                case 116: /* Field OnBehalfOfSubID */
                    proto_tree_add_string(fix_tree, hf_fix_OnBehalfOfSubID, tvb, offset, field_len, value);
                    break;
                case 117: /* Field QuoteID */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteID, tvb, offset, field_len, value);
                    break;
                case 118: /* Field NetMoney */
                    proto_tree_add_string(fix_tree, hf_fix_NetMoney, tvb, offset, field_len, value);
                    break;
                case 119: /* Field SettlCurrAmt */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrAmt, tvb, offset, field_len, value);
                    break;
                case 120: /* Field SettlCurrency */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrency, tvb, offset, field_len, value);
                    break;
                case 121: /* Field ForexReq */
                    proto_tree_add_string(fix_tree, hf_fix_ForexReq, tvb, offset, field_len, value);
                    break;
                case 122: /* Field OrigSendingTime */
                    proto_tree_add_string(fix_tree, hf_fix_OrigSendingTime, tvb, offset, field_len, value);
                    break;
                case 123: /* Field GapFillFlag */
                    proto_tree_add_string(fix_tree, hf_fix_GapFillFlag, tvb, offset, field_len, value);
                    break;
                case 124: /* Field NoExecs */
                    proto_tree_add_string(fix_tree, hf_fix_NoExecs, tvb, offset, field_len, value);
                    break;
                case 125: /* Field CxlType */
                    proto_tree_add_string(fix_tree, hf_fix_CxlType, tvb, offset, field_len, value);
                    break;
                case 126: /* Field ExpireTime */
                    proto_tree_add_string(fix_tree, hf_fix_ExpireTime, tvb, offset, field_len, value);
                    break;
                case 127: /* Field DKReason */
                    proto_tree_add_string(fix_tree, hf_fix_DKReason, tvb, offset, field_len, value);
                    break;
                case 128: /* Field DeliverToCompID */
                    proto_tree_add_string(fix_tree, hf_fix_DeliverToCompID, tvb, offset, field_len, value);
                    break;
                case 129: /* Field DeliverToSubID */
                    proto_tree_add_string(fix_tree, hf_fix_DeliverToSubID, tvb, offset, field_len, value);
                    break;
                case 130: /* Field IOINaturalFlag */
                    proto_tree_add_string(fix_tree, hf_fix_IOINaturalFlag, tvb, offset, field_len, value);
                    break;
                case 131: /* Field QuoteReqID */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteReqID, tvb, offset, field_len, value);
                    break;
                case 132: /* Field BidPx */
                    proto_tree_add_string(fix_tree, hf_fix_BidPx, tvb, offset, field_len, value);
                    break;
                case 133: /* Field OfferPx */
                    proto_tree_add_string(fix_tree, hf_fix_OfferPx, tvb, offset, field_len, value);
                    break;
                case 134: /* Field BidSize */
                    proto_tree_add_string(fix_tree, hf_fix_BidSize, tvb, offset, field_len, value);
                    break;
                case 135: /* Field OfferSize */
                    proto_tree_add_string(fix_tree, hf_fix_OfferSize, tvb, offset, field_len, value);
                    break;
                case 136: /* Field NoMiscFees */
                    proto_tree_add_string(fix_tree, hf_fix_NoMiscFees, tvb, offset, field_len, value);
                    break;
                case 137: /* Field MiscFeeAmt */
                    proto_tree_add_string(fix_tree, hf_fix_MiscFeeAmt, tvb, offset, field_len, value);
                    break;
                case 138: /* Field MiscFeeCurr */
                    proto_tree_add_string(fix_tree, hf_fix_MiscFeeCurr, tvb, offset, field_len, value);
                    break;
                case 139: /* Field MiscFeeType */
                    proto_tree_add_string(fix_tree, hf_fix_MiscFeeType, tvb, offset, field_len, value);
                    break;
                case 140: /* Field PrevClosePx */
                    proto_tree_add_string(fix_tree, hf_fix_PrevClosePx, tvb, offset, field_len, value);
                    break;
                case 141: /* Field ResetSeqNumFlag */
                    proto_tree_add_string(fix_tree, hf_fix_ResetSeqNumFlag, tvb, offset, field_len, value);
                    break;
                case 142: /* Field SenderLocationID */
                    proto_tree_add_string(fix_tree, hf_fix_SenderLocationID, tvb, offset, field_len, value);
                    break;
                case 143: /* Field TargetLocationID */
                    proto_tree_add_string(fix_tree, hf_fix_TargetLocationID, tvb, offset, field_len, value);
                    break;
                case 144: /* Field OnBehalfOfLocationID */
                    proto_tree_add_string(fix_tree, hf_fix_OnBehalfOfLocationID, tvb, offset, field_len, value);
                    break;
                case 145: /* Field DeliverToLocationID */
                    proto_tree_add_string(fix_tree, hf_fix_DeliverToLocationID, tvb, offset, field_len, value);
                    break;
                case 146: /* Field NoRelatedSym */
                    proto_tree_add_string(fix_tree, hf_fix_NoRelatedSym, tvb, offset, field_len, value);
                    break;
                case 147: /* Field Subject */
                    proto_tree_add_string(fix_tree, hf_fix_Subject, tvb, offset, field_len, value);
                    break;
                case 148: /* Field Headline */
                    proto_tree_add_string(fix_tree, hf_fix_Headline, tvb, offset, field_len, value);
                    break;
                case 149: /* Field URLLink */
                    proto_tree_add_string(fix_tree, hf_fix_URLLink, tvb, offset, field_len, value);
                    break;
                case 150: /* Field ExecType */
                    proto_tree_add_string(fix_tree, hf_fix_ExecType, tvb, offset, field_len, value);
                    break;
                case 151: /* Field LeavesQty */
                    proto_tree_add_string(fix_tree, hf_fix_LeavesQty, tvb, offset, field_len, value);
                    break;
                case 152: /* Field CashOrderQty */
                    proto_tree_add_string(fix_tree, hf_fix_CashOrderQty, tvb, offset, field_len, value);
                    break;
                case 153: /* Field AllocAvgPx */
                    proto_tree_add_string(fix_tree, hf_fix_AllocAvgPx, tvb, offset, field_len, value);
                    break;
                case 154: /* Field AllocNetMoney */
                    proto_tree_add_string(fix_tree, hf_fix_AllocNetMoney, tvb, offset, field_len, value);
                    break;
                case 155: /* Field SettlCurrFxRate */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrFxRate, tvb, offset, field_len, value);
                    break;
                case 156: /* Field SettlCurrFxRateCalc */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrFxRateCalc, tvb, offset, field_len, value);
                    break;
                case 157: /* Field NumDaysInterest */
                    proto_tree_add_string(fix_tree, hf_fix_NumDaysInterest, tvb, offset, field_len, value);
                    break;
                case 158: /* Field AccruedInterestRate */
                    proto_tree_add_string(fix_tree, hf_fix_AccruedInterestRate, tvb, offset, field_len, value);
                    break;
                case 159: /* Field AccruedInterestAmt */
                    proto_tree_add_string(fix_tree, hf_fix_AccruedInterestAmt, tvb, offset, field_len, value);
                    break;
                case 160: /* Field SettlInstMode */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstMode, tvb, offset, field_len, value);
                    break;
                case 161: /* Field AllocText */
                    proto_tree_add_string(fix_tree, hf_fix_AllocText, tvb, offset, field_len, value);
                    break;
                case 162: /* Field SettlInstID */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstID, tvb, offset, field_len, value);
                    break;
                case 163: /* Field SettlInstTransType */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstTransType, tvb, offset, field_len, value);
                    break;
                case 164: /* Field EmailThreadID */
                    proto_tree_add_string(fix_tree, hf_fix_EmailThreadID, tvb, offset, field_len, value);
                    break;
                case 165: /* Field SettlInstSource */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstSource, tvb, offset, field_len, value);
                    break;
                case 166: /* Field SettlLocation */
                    proto_tree_add_string(fix_tree, hf_fix_SettlLocation, tvb, offset, field_len, value);
                    break;
                case 167: /* Field SecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityType, tvb, offset, field_len, value);
                    break;
                case 168: /* Field EffectiveTime */
                    proto_tree_add_string(fix_tree, hf_fix_EffectiveTime, tvb, offset, field_len, value);
                    break;
                case 169: /* Field StandInstDbType */
                    proto_tree_add_string(fix_tree, hf_fix_StandInstDbType, tvb, offset, field_len, value);
                    break;
                case 170: /* Field StandInstDbName */
                    proto_tree_add_string(fix_tree, hf_fix_StandInstDbName, tvb, offset, field_len, value);
                    break;
                case 171: /* Field StandInstDbID */
                    proto_tree_add_string(fix_tree, hf_fix_StandInstDbID, tvb, offset, field_len, value);
                    break;
                case 172: /* Field SettlDeliveryType */
                    proto_tree_add_string(fix_tree, hf_fix_SettlDeliveryType, tvb, offset, field_len, value);
                    break;
                case 173: /* Field SettlDepositoryCode */
                    proto_tree_add_string(fix_tree, hf_fix_SettlDepositoryCode, tvb, offset, field_len, value);
                    break;
                case 174: /* Field SettlBrkrCode */
                    proto_tree_add_string(fix_tree, hf_fix_SettlBrkrCode, tvb, offset, field_len, value);
                    break;
                case 175: /* Field SettlInstCode */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstCode, tvb, offset, field_len, value);
                    break;
                case 176: /* Field SecuritySettlAgentName */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentName, tvb, offset, field_len, value);
                    break;
                case 177: /* Field SecuritySettlAgentCode */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentCode, tvb, offset, field_len, value);
                    break;
                case 178: /* Field SecuritySettlAgentAcctNum */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentAcctNum, tvb, offset, field_len, value);
                    break;
                case 179: /* Field SecuritySettlAgentAcctName */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentAcctName, tvb, offset, field_len, value);
                    break;
                case 180: /* Field SecuritySettlAgentContactName */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentContactName, tvb, offset, field_len, value);
                    break;
                case 181: /* Field SecuritySettlAgentContactPhone */
                    proto_tree_add_string(fix_tree, hf_fix_SecuritySettlAgentContactPhone, tvb, offset, field_len, value);
                    break;
                case 182: /* Field CashSettlAgentName */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentName, tvb, offset, field_len, value);
                    break;
                case 183: /* Field CashSettlAgentCode */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentCode, tvb, offset, field_len, value);
                    break;
                case 184: /* Field CashSettlAgentAcctNum */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentAcctNum, tvb, offset, field_len, value);
                    break;
                case 185: /* Field CashSettlAgentAcctName */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentAcctName, tvb, offset, field_len, value);
                    break;
                case 186: /* Field CashSettlAgentContactName */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentContactName, tvb, offset, field_len, value);
                    break;
                case 187: /* Field CashSettlAgentContactPhone */
                    proto_tree_add_string(fix_tree, hf_fix_CashSettlAgentContactPhone, tvb, offset, field_len, value);
                    break;
                case 188: /* Field BidSpotRate */
                    proto_tree_add_string(fix_tree, hf_fix_BidSpotRate, tvb, offset, field_len, value);
                    break;
                case 189: /* Field BidForwardPoints */
                    proto_tree_add_string(fix_tree, hf_fix_BidForwardPoints, tvb, offset, field_len, value);
                    break;
                case 190: /* Field OfferSpotRate */
                    proto_tree_add_string(fix_tree, hf_fix_OfferSpotRate, tvb, offset, field_len, value);
                    break;
                case 191: /* Field OfferForwardPoints */
                    proto_tree_add_string(fix_tree, hf_fix_OfferForwardPoints, tvb, offset, field_len, value);
                    break;
                case 192: /* Field OrderQty2 */
                    proto_tree_add_string(fix_tree, hf_fix_OrderQty2, tvb, offset, field_len, value);
                    break;
                case 193: /* Field FutSettDate2 */
                    proto_tree_add_string(fix_tree, hf_fix_FutSettDate2, tvb, offset, field_len, value);
                    break;
                case 194: /* Field LastSpotRate */
                    proto_tree_add_string(fix_tree, hf_fix_LastSpotRate, tvb, offset, field_len, value);
                    break;
                case 195: /* Field LastForwardPoints */
                    proto_tree_add_string(fix_tree, hf_fix_LastForwardPoints, tvb, offset, field_len, value);
                    break;
                case 196: /* Field AllocLinkID */
                    proto_tree_add_string(fix_tree, hf_fix_AllocLinkID, tvb, offset, field_len, value);
                    break;
                case 197: /* Field AllocLinkType */
                    proto_tree_add_string(fix_tree, hf_fix_AllocLinkType, tvb, offset, field_len, value);
                    break;
                case 198: /* Field SecondaryOrderID */
                    proto_tree_add_string(fix_tree, hf_fix_SecondaryOrderID, tvb, offset, field_len, value);
                    break;
                case 199: /* Field NoIOIQualifiers */
                    proto_tree_add_string(fix_tree, hf_fix_NoIOIQualifiers, tvb, offset, field_len, value);
                    break;
                case 200: /* Field MaturityMonthYear */
                    proto_tree_add_string(fix_tree, hf_fix_MaturityMonthYear, tvb, offset, field_len, value);
                    break;
                case 201: /* Field PutOrCall */
                    proto_tree_add_string(fix_tree, hf_fix_PutOrCall, tvb, offset, field_len, value);
                    break;
                case 202: /* Field StrikePrice */
                    proto_tree_add_string(fix_tree, hf_fix_StrikePrice, tvb, offset, field_len, value);
                    break;
                case 203: /* Field CoveredOrUncovered */
                    proto_tree_add_string(fix_tree, hf_fix_CoveredOrUncovered, tvb, offset, field_len, value);
                    break;
                case 204: /* Field CustomerOrFirm */
                    proto_tree_add_string(fix_tree, hf_fix_CustomerOrFirm, tvb, offset, field_len, value);
                    break;
                case 205: /* Field MaturityDay */
                    proto_tree_add_string(fix_tree, hf_fix_MaturityDay, tvb, offset, field_len, value);
                    break;
                case 206: /* Field OptAttribute */
                    proto_tree_add_string(fix_tree, hf_fix_OptAttribute, tvb, offset, field_len, value);
                    break;
                case 207: /* Field SecurityExchange */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityExchange, tvb, offset, field_len, value);
                    break;
                case 208: /* Field NotifyBrokerOfCredit */
                    proto_tree_add_string(fix_tree, hf_fix_NotifyBrokerOfCredit, tvb, offset, field_len, value);
                    break;
                case 209: /* Field AllocHandlInst */
                    proto_tree_add_string(fix_tree, hf_fix_AllocHandlInst, tvb, offset, field_len, value);
                    break;
                case 210: /* Field MaxShow */
                    proto_tree_add_string(fix_tree, hf_fix_MaxShow, tvb, offset, field_len, value);
                    break;
                case 211: /* Field PegDifference */
                    proto_tree_add_string(fix_tree, hf_fix_PegDifference, tvb, offset, field_len, value);
                    break;
                case 212: /* Field XmlDataLen */
                    proto_tree_add_string(fix_tree, hf_fix_XmlDataLen, tvb, offset, field_len, value);
                    break;
                case 213: /* Field XmlData */
                    proto_tree_add_string(fix_tree, hf_fix_XmlData, tvb, offset, field_len, value);
                    break;
                case 214: /* Field SettlInstRefID */
                    proto_tree_add_string(fix_tree, hf_fix_SettlInstRefID, tvb, offset, field_len, value);
                    break;
                case 215: /* Field NoRoutingIDs */
                    proto_tree_add_string(fix_tree, hf_fix_NoRoutingIDs, tvb, offset, field_len, value);
                    break;
                case 216: /* Field RoutingType */
                    proto_tree_add_string(fix_tree, hf_fix_RoutingType, tvb, offset, field_len, value);
                    break;
                case 217: /* Field RoutingID */
                    proto_tree_add_string(fix_tree, hf_fix_RoutingID, tvb, offset, field_len, value);
                    break;
                case 218: /* Field Spread */
                    proto_tree_add_string(fix_tree, hf_fix_Spread, tvb, offset, field_len, value);
                    break;
                case 219: /* Field Benchmark */
                    proto_tree_add_string(fix_tree, hf_fix_Benchmark, tvb, offset, field_len, value);
                    break;
                case 220: /* Field BenchmarkCurveCurrency */
                    proto_tree_add_string(fix_tree, hf_fix_BenchmarkCurveCurrency, tvb, offset, field_len, value);
                    break;
                case 221: /* Field BenchmarkCurveName */
                    proto_tree_add_string(fix_tree, hf_fix_BenchmarkCurveName, tvb, offset, field_len, value);
                    break;
                case 222: /* Field BenchmarkCurvePoint */
                    proto_tree_add_string(fix_tree, hf_fix_BenchmarkCurvePoint, tvb, offset, field_len, value);
                    break;
                case 223: /* Field CouponRate */
                    proto_tree_add_string(fix_tree, hf_fix_CouponRate, tvb, offset, field_len, value);
                    break;
                case 224: /* Field CouponPaymentDate */
                    proto_tree_add_string(fix_tree, hf_fix_CouponPaymentDate, tvb, offset, field_len, value);
                    break;
                case 225: /* Field IssueDate */
                    proto_tree_add_string(fix_tree, hf_fix_IssueDate, tvb, offset, field_len, value);
                    break;
                case 226: /* Field RepurchaseTerm */
                    proto_tree_add_string(fix_tree, hf_fix_RepurchaseTerm, tvb, offset, field_len, value);
                    break;
                case 227: /* Field RepurchaseRate */
                    proto_tree_add_string(fix_tree, hf_fix_RepurchaseRate, tvb, offset, field_len, value);
                    break;
                case 228: /* Field Factor */
                    proto_tree_add_string(fix_tree, hf_fix_Factor, tvb, offset, field_len, value);
                    break;
                case 229: /* Field TradeOriginationDate */
                    proto_tree_add_string(fix_tree, hf_fix_TradeOriginationDate, tvb, offset, field_len, value);
                    break;
                case 230: /* Field ExDate */
                    proto_tree_add_string(fix_tree, hf_fix_ExDate, tvb, offset, field_len, value);
                    break;
                case 231: /* Field ContractMultiplier */
                    proto_tree_add_string(fix_tree, hf_fix_ContractMultiplier, tvb, offset, field_len, value);
                    break;
                case 232: /* Field NoStipulations */
                    proto_tree_add_string(fix_tree, hf_fix_NoStipulations, tvb, offset, field_len, value);
                    break;
                case 233: /* Field StipulationType */
                    proto_tree_add_string(fix_tree, hf_fix_StipulationType, tvb, offset, field_len, value);
                    break;
                case 234: /* Field StipulationValue */
                    proto_tree_add_string(fix_tree, hf_fix_StipulationValue, tvb, offset, field_len, value);
                    break;
                case 235: /* Field YieldType */
                    proto_tree_add_string(fix_tree, hf_fix_YieldType, tvb, offset, field_len, value);
                    break;
                case 236: /* Field Yield */
                    proto_tree_add_string(fix_tree, hf_fix_Yield, tvb, offset, field_len, value);
                    break;
                case 237: /* Field TotalTakedown */
                    proto_tree_add_string(fix_tree, hf_fix_TotalTakedown, tvb, offset, field_len, value);
                    break;
                case 238: /* Field Concession */
                    proto_tree_add_string(fix_tree, hf_fix_Concession, tvb, offset, field_len, value);
                    break;
                case 239: /* Field RepoCollateralSecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_RepoCollateralSecurityType, tvb, offset, field_len, value);
                    break;
                case 240: /* Field RedemptionDate */
                    proto_tree_add_string(fix_tree, hf_fix_RedemptionDate, tvb, offset, field_len, value);
                    break;
                case 241: /* Field UnderlyingCouponPaymentDate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingCouponPaymentDate, tvb, offset, field_len, value);
                    break;
                case 242: /* Field UnderlyingIssueDate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingIssueDate, tvb, offset, field_len, value);
                    break;
                case 243: /* Field UnderlyingRepoCollateralSecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingRepoCollateralSecurityType, tvb, offset, field_len, value);
                    break;
                case 244: /* Field UnderlyingRepurchaseTerm */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingRepurchaseTerm, tvb, offset, field_len, value);
                    break;
                case 245: /* Field UnderlyingRepurchaseRate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingRepurchaseRate, tvb, offset, field_len, value);
                    break;
                case 246: /* Field UnderlyingFactor */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingFactor, tvb, offset, field_len, value);
                    break;
                case 247: /* Field UnderlyingRedemptionDate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingRedemptionDate, tvb, offset, field_len, value);
                    break;
                case 248: /* Field LegCouponPaymentDate */
                    proto_tree_add_string(fix_tree, hf_fix_LegCouponPaymentDate, tvb, offset, field_len, value);
                    break;
                case 249: /* Field LegIssueDate */
                    proto_tree_add_string(fix_tree, hf_fix_LegIssueDate, tvb, offset, field_len, value);
                    break;
                case 250: /* Field LegRepoCollateralSecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_LegRepoCollateralSecurityType, tvb, offset, field_len, value);
                    break;
                case 251: /* Field LegRepurchaseTerm */
                    proto_tree_add_string(fix_tree, hf_fix_LegRepurchaseTerm, tvb, offset, field_len, value);
                    break;
                case 252: /* Field LegRepurchaseRate */
                    proto_tree_add_string(fix_tree, hf_fix_LegRepurchaseRate, tvb, offset, field_len, value);
                    break;
                case 253: /* Field LegFactor */
                    proto_tree_add_string(fix_tree, hf_fix_LegFactor, tvb, offset, field_len, value);
                    break;
                case 254: /* Field LegRedemptionDate */
                    proto_tree_add_string(fix_tree, hf_fix_LegRedemptionDate, tvb, offset, field_len, value);
                    break;
                case 255: /* Field CreditRating */
                    proto_tree_add_string(fix_tree, hf_fix_CreditRating, tvb, offset, field_len, value);
                    break;
                case 256: /* Field UnderlyingCreditRating */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingCreditRating, tvb, offset, field_len, value);
                    break;
                case 257: /* Field LegCreditRating */
                    proto_tree_add_string(fix_tree, hf_fix_LegCreditRating, tvb, offset, field_len, value);
                    break;
                case 258: /* Field TradedFlatSwitch */
                    proto_tree_add_string(fix_tree, hf_fix_TradedFlatSwitch, tvb, offset, field_len, value);
                    break;
                case 259: /* Field BasisFeatureDate */
                    proto_tree_add_string(fix_tree, hf_fix_BasisFeatureDate, tvb, offset, field_len, value);
                    break;
                case 260: /* Field BasisFeaturePrice */
                    proto_tree_add_string(fix_tree, hf_fix_BasisFeaturePrice, tvb, offset, field_len, value);
                    break;
                case 261: /* Field ReservedAllocated */
                    proto_tree_add_string(fix_tree, hf_fix_ReservedAllocated, tvb, offset, field_len, value);
                    break;
                case 262: /* Field MDReqID */
                    proto_tree_add_string(fix_tree, hf_fix_MDReqID, tvb, offset, field_len, value);
                    break;
                case 263: /* Field SubscriptionRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_SubscriptionRequestType, tvb, offset, field_len, value);
                    break;
                case 264: /* Field MarketDepth */
                    proto_tree_add_string(fix_tree, hf_fix_MarketDepth, tvb, offset, field_len, value);
                    break;
                case 265: /* Field MDUpdateType */
                    proto_tree_add_string(fix_tree, hf_fix_MDUpdateType, tvb, offset, field_len, value);
                    break;
                case 266: /* Field AggregatedBook */
                    proto_tree_add_string(fix_tree, hf_fix_AggregatedBook, tvb, offset, field_len, value);
                    break;
                case 267: /* Field NoMDEntryTypes */
                    proto_tree_add_string(fix_tree, hf_fix_NoMDEntryTypes, tvb, offset, field_len, value);
                    break;
                case 268: /* Field NoMDEntries */
                    proto_tree_add_string(fix_tree, hf_fix_NoMDEntries, tvb, offset, field_len, value);
                    break;
                case 269: /* Field MDEntryType */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryType, tvb, offset, field_len, value);
                    break;
                case 270: /* Field MDEntryPx */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryPx, tvb, offset, field_len, value);
                    break;
                case 271: /* Field MDEntrySize */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntrySize, tvb, offset, field_len, value);
                    break;
                case 272: /* Field MDEntryDate */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryDate, tvb, offset, field_len, value);
                    break;
                case 273: /* Field MDEntryTime */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryTime, tvb, offset, field_len, value);
                    break;
                case 274: /* Field TickDirection */
                    proto_tree_add_string(fix_tree, hf_fix_TickDirection, tvb, offset, field_len, value);
                    break;
                case 275: /* Field MDMkt */
                    proto_tree_add_string(fix_tree, hf_fix_MDMkt, tvb, offset, field_len, value);
                    break;
                case 276: /* Field QuoteCondition */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteCondition, tvb, offset, field_len, value);
                    break;
                case 277: /* Field TradeCondition */
                    proto_tree_add_string(fix_tree, hf_fix_TradeCondition, tvb, offset, field_len, value);
                    break;
                case 278: /* Field MDEntryID */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryID, tvb, offset, field_len, value);
                    break;
                case 279: /* Field MDUpdateAction */
                    proto_tree_add_string(fix_tree, hf_fix_MDUpdateAction, tvb, offset, field_len, value);
                    break;
                case 280: /* Field MDEntryRefID */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryRefID, tvb, offset, field_len, value);
                    break;
                case 281: /* Field MDReqRejReason */
                    proto_tree_add_string(fix_tree, hf_fix_MDReqRejReason, tvb, offset, field_len, value);
                    break;
                case 282: /* Field MDEntryOriginator */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryOriginator, tvb, offset, field_len, value);
                    break;
                case 283: /* Field LocationID */
                    proto_tree_add_string(fix_tree, hf_fix_LocationID, tvb, offset, field_len, value);
                    break;
                case 284: /* Field DeskID */
                    proto_tree_add_string(fix_tree, hf_fix_DeskID, tvb, offset, field_len, value);
                    break;
                case 285: /* Field DeleteReason */
                    proto_tree_add_string(fix_tree, hf_fix_DeleteReason, tvb, offset, field_len, value);
                    break;
                case 286: /* Field OpenCloseSettleFlag */
                    proto_tree_add_string(fix_tree, hf_fix_OpenCloseSettleFlag, tvb, offset, field_len, value);
                    break;
                case 287: /* Field SellerDays */
                    proto_tree_add_string(fix_tree, hf_fix_SellerDays, tvb, offset, field_len, value);
                    break;
                case 288: /* Field MDEntryBuyer */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryBuyer, tvb, offset, field_len, value);
                    break;
                case 289: /* Field MDEntrySeller */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntrySeller, tvb, offset, field_len, value);
                    break;
                case 290: /* Field MDEntryPositionNo */
                    proto_tree_add_string(fix_tree, hf_fix_MDEntryPositionNo, tvb, offset, field_len, value);
                    break;
                case 291: /* Field FinancialStatus */
                    proto_tree_add_string(fix_tree, hf_fix_FinancialStatus, tvb, offset, field_len, value);
                    break;
                case 292: /* Field CorporateAction */
                    proto_tree_add_string(fix_tree, hf_fix_CorporateAction, tvb, offset, field_len, value);
                    break;
                case 293: /* Field DefBidSize */
                    proto_tree_add_string(fix_tree, hf_fix_DefBidSize, tvb, offset, field_len, value);
                    break;
                case 294: /* Field DefOfferSize */
                    proto_tree_add_string(fix_tree, hf_fix_DefOfferSize, tvb, offset, field_len, value);
                    break;
                case 295: /* Field NoQuoteEntries */
                    proto_tree_add_string(fix_tree, hf_fix_NoQuoteEntries, tvb, offset, field_len, value);
                    break;
                case 296: /* Field NoQuoteSets */
                    proto_tree_add_string(fix_tree, hf_fix_NoQuoteSets, tvb, offset, field_len, value);
                    break;
                case 297: /* Field QuoteStatus */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteStatus, tvb, offset, field_len, value);
                    break;
                case 298: /* Field QuoteCancelType */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteCancelType, tvb, offset, field_len, value);
                    break;
                case 299: /* Field QuoteEntryID */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteEntryID, tvb, offset, field_len, value);
                    break;
                case 300: /* Field QuoteRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteRejectReason, tvb, offset, field_len, value);
                    break;
                case 301: /* Field QuoteResponseLevel */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteResponseLevel, tvb, offset, field_len, value);
                    break;
                case 302: /* Field QuoteSetID */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteSetID, tvb, offset, field_len, value);
                    break;
                case 303: /* Field QuoteRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteRequestType, tvb, offset, field_len, value);
                    break;
                case 304: /* Field TotQuoteEntries */
                    proto_tree_add_string(fix_tree, hf_fix_TotQuoteEntries, tvb, offset, field_len, value);
                    break;
                case 305: /* Field UnderlyingSecurityIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityIDSource, tvb, offset, field_len, value);
                    break;
                case 306: /* Field UnderlyingIssuer */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingIssuer, tvb, offset, field_len, value);
                    break;
                case 307: /* Field UnderlyingSecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityDesc, tvb, offset, field_len, value);
                    break;
                case 308: /* Field UnderlyingSecurityExchange */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityExchange, tvb, offset, field_len, value);
                    break;
                case 309: /* Field UnderlyingSecurityID */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityID, tvb, offset, field_len, value);
                    break;
                case 310: /* Field UnderlyingSecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityType, tvb, offset, field_len, value);
                    break;
                case 311: /* Field UnderlyingSymbol */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSymbol, tvb, offset, field_len, value);
                    break;
                case 312: /* Field UnderlyingSymbolSfx */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSymbolSfx, tvb, offset, field_len, value);
                    break;
                case 313: /* Field UnderlyingMaturityMonthYear */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingMaturityMonthYear, tvb, offset, field_len, value);
                    break;
                case 314: /* Field UnderlyingMaturityDay */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingMaturityDay, tvb, offset, field_len, value);
                    break;
                case 315: /* Field UnderlyingPutOrCall */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingPutOrCall, tvb, offset, field_len, value);
                    break;
                case 316: /* Field UnderlyingStrikePrice */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingStrikePrice, tvb, offset, field_len, value);
                    break;
                case 317: /* Field UnderlyingOptAttribute */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingOptAttribute, tvb, offset, field_len, value);
                    break;
                case 318: /* Field Underlying */
                    proto_tree_add_string(fix_tree, hf_fix_Underlying, tvb, offset, field_len, value);
                    break;
                case 319: /* Field RatioQty */
                    proto_tree_add_string(fix_tree, hf_fix_RatioQty, tvb, offset, field_len, value);
                    break;
                case 320: /* Field SecurityReqID */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityReqID, tvb, offset, field_len, value);
                    break;
                case 321: /* Field SecurityRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityRequestType, tvb, offset, field_len, value);
                    break;
                case 322: /* Field SecurityResponseID */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityResponseID, tvb, offset, field_len, value);
                    break;
                case 323: /* Field SecurityResponseType */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityResponseType, tvb, offset, field_len, value);
                    break;
                case 324: /* Field SecurityStatusReqID */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityStatusReqID, tvb, offset, field_len, value);
                    break;
                case 325: /* Field UnsolicitedIndicator */
                    proto_tree_add_string(fix_tree, hf_fix_UnsolicitedIndicator, tvb, offset, field_len, value);
                    break;
                case 326: /* Field SecurityTradingStatus */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityTradingStatus, tvb, offset, field_len, value);
                    break;
                case 327: /* Field HaltReason */
                    proto_tree_add_string(fix_tree, hf_fix_HaltReason, tvb, offset, field_len, value);
                    break;
                case 328: /* Field InViewOfCommon */
                    proto_tree_add_string(fix_tree, hf_fix_InViewOfCommon, tvb, offset, field_len, value);
                    break;
                case 329: /* Field DueToRelated */
                    proto_tree_add_string(fix_tree, hf_fix_DueToRelated, tvb, offset, field_len, value);
                    break;
                case 330: /* Field BuyVolume */
                    proto_tree_add_string(fix_tree, hf_fix_BuyVolume, tvb, offset, field_len, value);
                    break;
                case 331: /* Field SellVolume */
                    proto_tree_add_string(fix_tree, hf_fix_SellVolume, tvb, offset, field_len, value);
                    break;
                case 332: /* Field HighPx */
                    proto_tree_add_string(fix_tree, hf_fix_HighPx, tvb, offset, field_len, value);
                    break;
                case 333: /* Field LowPx */
                    proto_tree_add_string(fix_tree, hf_fix_LowPx, tvb, offset, field_len, value);
                    break;
                case 334: /* Field Adjustment */
                    proto_tree_add_string(fix_tree, hf_fix_Adjustment, tvb, offset, field_len, value);
                    break;
                case 335: /* Field TradSesReqID */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesReqID, tvb, offset, field_len, value);
                    break;
                case 336: /* Field TradingSessionID */
                    proto_tree_add_string(fix_tree, hf_fix_TradingSessionID, tvb, offset, field_len, value);
                    break;
                case 337: /* Field ContraTrader */
                    proto_tree_add_string(fix_tree, hf_fix_ContraTrader, tvb, offset, field_len, value);
                    break;
                case 338: /* Field TradSesMethod */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesMethod, tvb, offset, field_len, value);
                    break;
                case 339: /* Field TradSesMode */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesMode, tvb, offset, field_len, value);
                    break;
                case 340: /* Field TradSesStatus */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesStatus, tvb, offset, field_len, value);
                    break;
                case 341: /* Field TradSesStartTime */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesStartTime, tvb, offset, field_len, value);
                    break;
                case 342: /* Field TradSesOpenTime */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesOpenTime, tvb, offset, field_len, value);
                    break;
                case 343: /* Field TradSesPreCloseTime */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesPreCloseTime, tvb, offset, field_len, value);
                    break;
                case 344: /* Field TradSesCloseTime */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesCloseTime, tvb, offset, field_len, value);
                    break;
                case 345: /* Field TradSesEndTime */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesEndTime, tvb, offset, field_len, value);
                    break;
                case 346: /* Field NumberOfOrders */
                    proto_tree_add_string(fix_tree, hf_fix_NumberOfOrders, tvb, offset, field_len, value);
                    break;
                case 347: /* Field MessageEncoding */
                    proto_tree_add_string(fix_tree, hf_fix_MessageEncoding, tvb, offset, field_len, value);
                    break;
                case 348: /* Field EncodedIssuerLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedIssuerLen, tvb, offset, field_len, value);
                    break;
                case 349: /* Field EncodedIssuer */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedIssuer, tvb, offset, field_len, value);
                    break;
                case 350: /* Field EncodedSecurityDescLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedSecurityDescLen, tvb, offset, field_len, value);
                    break;
                case 351: /* Field EncodedSecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedSecurityDesc, tvb, offset, field_len, value);
                    break;
                case 352: /* Field EncodedListExecInstLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedListExecInstLen, tvb, offset, field_len, value);
                    break;
                case 353: /* Field EncodedListExecInst */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedListExecInst, tvb, offset, field_len, value);
                    break;
                case 354: /* Field EncodedTextLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedTextLen, tvb, offset, field_len, value);
                    break;
                case 355: /* Field EncodedText */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedText, tvb, offset, field_len, value);
                    break;
                case 356: /* Field EncodedSubjectLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedSubjectLen, tvb, offset, field_len, value);
                    break;
                case 357: /* Field EncodedSubject */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedSubject, tvb, offset, field_len, value);
                    break;
                case 358: /* Field EncodedHeadlineLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedHeadlineLen, tvb, offset, field_len, value);
                    break;
                case 359: /* Field EncodedHeadline */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedHeadline, tvb, offset, field_len, value);
                    break;
                case 360: /* Field EncodedAllocTextLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedAllocTextLen, tvb, offset, field_len, value);
                    break;
                case 361: /* Field EncodedAllocText */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedAllocText, tvb, offset, field_len, value);
                    break;
                case 362: /* Field EncodedUnderlyingIssuerLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedUnderlyingIssuerLen, tvb, offset, field_len, value);
                    break;
                case 363: /* Field EncodedUnderlyingIssuer */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedUnderlyingIssuer, tvb, offset, field_len, value);
                    break;
                case 364: /* Field EncodedUnderlyingSecurityDescLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedUnderlyingSecurityDescLen, tvb, offset, field_len, value);
                    break;
                case 365: /* Field EncodedUnderlyingSecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedUnderlyingSecurityDesc, tvb, offset, field_len, value);
                    break;
                case 366: /* Field AllocPrice */
                    proto_tree_add_string(fix_tree, hf_fix_AllocPrice, tvb, offset, field_len, value);
                    break;
                case 367: /* Field QuoteSetValidUntilTime */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteSetValidUntilTime, tvb, offset, field_len, value);
                    break;
                case 368: /* Field QuoteEntryRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteEntryRejectReason, tvb, offset, field_len, value);
                    break;
                case 369: /* Field LastMsgSeqNumProcessed */
                    proto_tree_add_string(fix_tree, hf_fix_LastMsgSeqNumProcessed, tvb, offset, field_len, value);
                    break;
                case 370: /* Field OnBehalfOfSendingTime */
                    proto_tree_add_string(fix_tree, hf_fix_OnBehalfOfSendingTime, tvb, offset, field_len, value);
                    break;
                case 371: /* Field RefTagID */
                    proto_tree_add_string(fix_tree, hf_fix_RefTagID, tvb, offset, field_len, value);
                    break;
                case 372: /* Field RefMsgType */
                    proto_tree_add_string(fix_tree, hf_fix_RefMsgType, tvb, offset, field_len, value);
                    break;
                case 373: /* Field SessionRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_SessionRejectReason, tvb, offset, field_len, value);
                    break;
                case 374: /* Field BidRequestTransType */
                    proto_tree_add_string(fix_tree, hf_fix_BidRequestTransType, tvb, offset, field_len, value);
                    break;
                case 375: /* Field ContraBroker */
                    proto_tree_add_string(fix_tree, hf_fix_ContraBroker, tvb, offset, field_len, value);
                    break;
                case 376: /* Field ComplianceID */
                    proto_tree_add_string(fix_tree, hf_fix_ComplianceID, tvb, offset, field_len, value);
                    break;
                case 377: /* Field SolicitedFlag */
                    proto_tree_add_string(fix_tree, hf_fix_SolicitedFlag, tvb, offset, field_len, value);
                    break;
                case 378: /* Field ExecRestatementReason */
                    proto_tree_add_string(fix_tree, hf_fix_ExecRestatementReason, tvb, offset, field_len, value);
                    break;
                case 379: /* Field BusinessRejectRefID */
                    proto_tree_add_string(fix_tree, hf_fix_BusinessRejectRefID, tvb, offset, field_len, value);
                    break;
                case 380: /* Field BusinessRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_BusinessRejectReason, tvb, offset, field_len, value);
                    break;
                case 381: /* Field GrossTradeAmt */
                    proto_tree_add_string(fix_tree, hf_fix_GrossTradeAmt, tvb, offset, field_len, value);
                    break;
                case 382: /* Field NoContraBrokers */
                    proto_tree_add_string(fix_tree, hf_fix_NoContraBrokers, tvb, offset, field_len, value);
                    break;
                case 383: /* Field MaxMessageSize */
                    proto_tree_add_string(fix_tree, hf_fix_MaxMessageSize, tvb, offset, field_len, value);
                    break;
                case 384: /* Field NoMsgTypes */
                    proto_tree_add_string(fix_tree, hf_fix_NoMsgTypes, tvb, offset, field_len, value);
                    break;
                case 385: /* Field MsgDirection */
                    proto_tree_add_string(fix_tree, hf_fix_MsgDirection, tvb, offset, field_len, value);
                    break;
                case 386: /* Field NoTradingSessions */
                    proto_tree_add_string(fix_tree, hf_fix_NoTradingSessions, tvb, offset, field_len, value);
                    break;
                case 387: /* Field TotalVolumeTraded */
                    proto_tree_add_string(fix_tree, hf_fix_TotalVolumeTraded, tvb, offset, field_len, value);
                    break;
                case 388: /* Field DiscretionInst */
                    proto_tree_add_string(fix_tree, hf_fix_DiscretionInst, tvb, offset, field_len, value);
                    break;
                case 389: /* Field DiscretionOffset */
                    proto_tree_add_string(fix_tree, hf_fix_DiscretionOffset, tvb, offset, field_len, value);
                    break;
                case 390: /* Field BidID */
                    proto_tree_add_string(fix_tree, hf_fix_BidID, tvb, offset, field_len, value);
                    break;
                case 391: /* Field ClientBidID */
                    proto_tree_add_string(fix_tree, hf_fix_ClientBidID, tvb, offset, field_len, value);
                    break;
                case 392: /* Field ListName */
                    proto_tree_add_string(fix_tree, hf_fix_ListName, tvb, offset, field_len, value);
                    break;
                case 393: /* Field TotalNumSecurities */
                    proto_tree_add_string(fix_tree, hf_fix_TotalNumSecurities, tvb, offset, field_len, value);
                    break;
                case 394: /* Field BidType */
                    proto_tree_add_string(fix_tree, hf_fix_BidType, tvb, offset, field_len, value);
                    break;
                case 395: /* Field NumTickets */
                    proto_tree_add_string(fix_tree, hf_fix_NumTickets, tvb, offset, field_len, value);
                    break;
                case 396: /* Field SideValue1 */
                    proto_tree_add_string(fix_tree, hf_fix_SideValue1, tvb, offset, field_len, value);
                    break;
                case 397: /* Field SideValue2 */
                    proto_tree_add_string(fix_tree, hf_fix_SideValue2, tvb, offset, field_len, value);
                    break;
                case 398: /* Field NoBidDescriptors */
                    proto_tree_add_string(fix_tree, hf_fix_NoBidDescriptors, tvb, offset, field_len, value);
                    break;
                case 399: /* Field BidDescriptorType */
                    proto_tree_add_string(fix_tree, hf_fix_BidDescriptorType, tvb, offset, field_len, value);
                    break;
                case 400: /* Field BidDescriptor */
                    proto_tree_add_string(fix_tree, hf_fix_BidDescriptor, tvb, offset, field_len, value);
                    break;
                case 401: /* Field SideValueInd */
                    proto_tree_add_string(fix_tree, hf_fix_SideValueInd, tvb, offset, field_len, value);
                    break;
                case 402: /* Field LiquidityPctLow */
                    proto_tree_add_string(fix_tree, hf_fix_LiquidityPctLow, tvb, offset, field_len, value);
                    break;
                case 403: /* Field LiquidityPctHigh */
                    proto_tree_add_string(fix_tree, hf_fix_LiquidityPctHigh, tvb, offset, field_len, value);
                    break;
                case 404: /* Field LiquidityValue */
                    proto_tree_add_string(fix_tree, hf_fix_LiquidityValue, tvb, offset, field_len, value);
                    break;
                case 405: /* Field EFPTrackingError */
                    proto_tree_add_string(fix_tree, hf_fix_EFPTrackingError, tvb, offset, field_len, value);
                    break;
                case 406: /* Field FairValue */
                    proto_tree_add_string(fix_tree, hf_fix_FairValue, tvb, offset, field_len, value);
                    break;
                case 407: /* Field OutsideIndexPct */
                    proto_tree_add_string(fix_tree, hf_fix_OutsideIndexPct, tvb, offset, field_len, value);
                    break;
                case 408: /* Field ValueOfFutures */
                    proto_tree_add_string(fix_tree, hf_fix_ValueOfFutures, tvb, offset, field_len, value);
                    break;
                case 409: /* Field LiquidityIndType */
                    proto_tree_add_string(fix_tree, hf_fix_LiquidityIndType, tvb, offset, field_len, value);
                    break;
                case 410: /* Field WtAverageLiquidity */
                    proto_tree_add_string(fix_tree, hf_fix_WtAverageLiquidity, tvb, offset, field_len, value);
                    break;
                case 411: /* Field ExchangeForPhysical */
                    proto_tree_add_string(fix_tree, hf_fix_ExchangeForPhysical, tvb, offset, field_len, value);
                    break;
                case 412: /* Field OutMainCntryUIndex */
                    proto_tree_add_string(fix_tree, hf_fix_OutMainCntryUIndex, tvb, offset, field_len, value);
                    break;
                case 413: /* Field CrossPercent */
                    proto_tree_add_string(fix_tree, hf_fix_CrossPercent, tvb, offset, field_len, value);
                    break;
                case 414: /* Field ProgRptReqs */
                    proto_tree_add_string(fix_tree, hf_fix_ProgRptReqs, tvb, offset, field_len, value);
                    break;
                case 415: /* Field ProgPeriodInterval */
                    proto_tree_add_string(fix_tree, hf_fix_ProgPeriodInterval, tvb, offset, field_len, value);
                    break;
                case 416: /* Field IncTaxInd */
                    proto_tree_add_string(fix_tree, hf_fix_IncTaxInd, tvb, offset, field_len, value);
                    break;
                case 417: /* Field NumBidders */
                    proto_tree_add_string(fix_tree, hf_fix_NumBidders, tvb, offset, field_len, value);
                    break;
                case 418: /* Field TradeType */
                    proto_tree_add_string(fix_tree, hf_fix_TradeType, tvb, offset, field_len, value);
                    break;
                case 419: /* Field BasisPxType */
                    proto_tree_add_string(fix_tree, hf_fix_BasisPxType, tvb, offset, field_len, value);
                    break;
                case 420: /* Field NoBidComponents */
                    proto_tree_add_string(fix_tree, hf_fix_NoBidComponents, tvb, offset, field_len, value);
                    break;
                case 421: /* Field Country */
                    proto_tree_add_string(fix_tree, hf_fix_Country, tvb, offset, field_len, value);
                    break;
                case 422: /* Field TotNoStrikes */
                    proto_tree_add_string(fix_tree, hf_fix_TotNoStrikes, tvb, offset, field_len, value);
                    break;
                case 423: /* Field PriceType */
                    proto_tree_add_string(fix_tree, hf_fix_PriceType, tvb, offset, field_len, value);
                    break;
                case 424: /* Field DayOrderQty */
                    proto_tree_add_string(fix_tree, hf_fix_DayOrderQty, tvb, offset, field_len, value);
                    break;
                case 425: /* Field DayCumQty */
                    proto_tree_add_string(fix_tree, hf_fix_DayCumQty, tvb, offset, field_len, value);
                    break;
                case 426: /* Field DayAvgPx */
                    proto_tree_add_string(fix_tree, hf_fix_DayAvgPx, tvb, offset, field_len, value);
                    break;
                case 427: /* Field GTBookingInst */
                    proto_tree_add_string(fix_tree, hf_fix_GTBookingInst, tvb, offset, field_len, value);
                    break;
                case 428: /* Field NoStrikes */
                    proto_tree_add_string(fix_tree, hf_fix_NoStrikes, tvb, offset, field_len, value);
                    break;
                case 429: /* Field ListStatusType */
                    proto_tree_add_string(fix_tree, hf_fix_ListStatusType, tvb, offset, field_len, value);
                    break;
                case 430: /* Field NetGrossInd */
                    proto_tree_add_string(fix_tree, hf_fix_NetGrossInd, tvb, offset, field_len, value);
                    break;
                case 431: /* Field ListOrderStatus */
                    proto_tree_add_string(fix_tree, hf_fix_ListOrderStatus, tvb, offset, field_len, value);
                    break;
                case 432: /* Field ExpireDate */
                    proto_tree_add_string(fix_tree, hf_fix_ExpireDate, tvb, offset, field_len, value);
                    break;
                case 433: /* Field ListExecInstType */
                    proto_tree_add_string(fix_tree, hf_fix_ListExecInstType, tvb, offset, field_len, value);
                    break;
                case 434: /* Field CxlRejResponseTo */
                    proto_tree_add_string(fix_tree, hf_fix_CxlRejResponseTo, tvb, offset, field_len, value);
                    break;
                case 435: /* Field UnderlyingCouponRate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingCouponRate, tvb, offset, field_len, value);
                    break;
                case 436: /* Field UnderlyingContractMultiplier */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingContractMultiplier, tvb, offset, field_len, value);
                    break;
                case 437: /* Field ContraTradeQty */
                    proto_tree_add_string(fix_tree, hf_fix_ContraTradeQty, tvb, offset, field_len, value);
                    break;
                case 438: /* Field ContraTradeTime */
                    proto_tree_add_string(fix_tree, hf_fix_ContraTradeTime, tvb, offset, field_len, value);
                    break;
                case 439: /* Field ClearingFirm */
                    proto_tree_add_string(fix_tree, hf_fix_ClearingFirm, tvb, offset, field_len, value);
                    break;
                case 440: /* Field ClearingAccount */
                    proto_tree_add_string(fix_tree, hf_fix_ClearingAccount, tvb, offset, field_len, value);
                    break;
                case 441: /* Field LiquidityNumSecurities */
                    proto_tree_add_string(fix_tree, hf_fix_LiquidityNumSecurities, tvb, offset, field_len, value);
                    break;
                case 442: /* Field MultiLegReportingType */
                    proto_tree_add_string(fix_tree, hf_fix_MultiLegReportingType, tvb, offset, field_len, value);
                    break;
                case 443: /* Field StrikeTime */
                    proto_tree_add_string(fix_tree, hf_fix_StrikeTime, tvb, offset, field_len, value);
                    break;
                case 444: /* Field ListStatusText */
                    proto_tree_add_string(fix_tree, hf_fix_ListStatusText, tvb, offset, field_len, value);
                    break;
                case 445: /* Field EncodedListStatusTextLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedListStatusTextLen, tvb, offset, field_len, value);
                    break;
                case 446: /* Field EncodedListStatusText */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedListStatusText, tvb, offset, field_len, value);
                    break;
                case 447: /* Field PartyIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_PartyIDSource, tvb, offset, field_len, value);
                    break;
                case 448: /* Field PartyID */
                    proto_tree_add_string(fix_tree, hf_fix_PartyID, tvb, offset, field_len, value);
                    break;
                case 449: /* Field TotalVolumeTradedDate */
                    proto_tree_add_string(fix_tree, hf_fix_TotalVolumeTradedDate, tvb, offset, field_len, value);
                    break;
                case 450: /* Field TotalVolumeTradedTime */
                    proto_tree_add_string(fix_tree, hf_fix_TotalVolumeTradedTime, tvb, offset, field_len, value);
                    break;
                case 451: /* Field NetChgPrevDay */
                    proto_tree_add_string(fix_tree, hf_fix_NetChgPrevDay, tvb, offset, field_len, value);
                    break;
                case 452: /* Field PartyRole */
                    proto_tree_add_string(fix_tree, hf_fix_PartyRole, tvb, offset, field_len, value);
                    break;
                case 453: /* Field NoPartyIDs */
                    proto_tree_add_string(fix_tree, hf_fix_NoPartyIDs, tvb, offset, field_len, value);
                    break;
                case 454: /* Field NoSecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_NoSecurityAltID, tvb, offset, field_len, value);
                    break;
                case 455: /* Field SecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityAltID, tvb, offset, field_len, value);
                    break;
                case 456: /* Field SecurityAltIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityAltIDSource, tvb, offset, field_len, value);
                    break;
                case 457: /* Field NoUnderlyingSecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_NoUnderlyingSecurityAltID, tvb, offset, field_len, value);
                    break;
                case 458: /* Field UnderlyingSecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityAltID, tvb, offset, field_len, value);
                    break;
                case 459: /* Field UnderlyingSecurityAltIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingSecurityAltIDSource, tvb, offset, field_len, value);
                    break;
                case 460: /* Field Product */
                    proto_tree_add_string(fix_tree, hf_fix_Product, tvb, offset, field_len, value);
                    break;
                case 461: /* Field CFICode */
                    proto_tree_add_string(fix_tree, hf_fix_CFICode, tvb, offset, field_len, value);
                    break;
                case 462: /* Field UnderlyingProduct */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingProduct, tvb, offset, field_len, value);
                    break;
                case 463: /* Field UnderlyingCFICode */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingCFICode, tvb, offset, field_len, value);
                    break;
                case 464: /* Field TestMessageIndicator */
                    proto_tree_add_string(fix_tree, hf_fix_TestMessageIndicator, tvb, offset, field_len, value);
                    break;
                case 465: /* Field QuantityType */
                    proto_tree_add_string(fix_tree, hf_fix_QuantityType, tvb, offset, field_len, value);
                    break;
                case 466: /* Field BookingRefID */
                    proto_tree_add_string(fix_tree, hf_fix_BookingRefID, tvb, offset, field_len, value);
                    break;
                case 467: /* Field IndividualAllocID */
                    proto_tree_add_string(fix_tree, hf_fix_IndividualAllocID, tvb, offset, field_len, value);
                    break;
                case 468: /* Field RoundingDirection */
                    proto_tree_add_string(fix_tree, hf_fix_RoundingDirection, tvb, offset, field_len, value);
                    break;
                case 469: /* Field RoundingModulus */
                    proto_tree_add_string(fix_tree, hf_fix_RoundingModulus, tvb, offset, field_len, value);
                    break;
                case 470: /* Field CountryOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_CountryOfIssue, tvb, offset, field_len, value);
                    break;
                case 471: /* Field StateOrProvinceOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_StateOrProvinceOfIssue, tvb, offset, field_len, value);
                    break;
                case 472: /* Field LocaleOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_LocaleOfIssue, tvb, offset, field_len, value);
                    break;
                case 473: /* Field NoRegistDtls */
                    proto_tree_add_string(fix_tree, hf_fix_NoRegistDtls, tvb, offset, field_len, value);
                    break;
                case 474: /* Field MailingDtls */
                    proto_tree_add_string(fix_tree, hf_fix_MailingDtls, tvb, offset, field_len, value);
                    break;
                case 475: /* Field InvestorCountryOfResidence */
                    proto_tree_add_string(fix_tree, hf_fix_InvestorCountryOfResidence, tvb, offset, field_len, value);
                    break;
                case 476: /* Field PaymentRef */
                    proto_tree_add_string(fix_tree, hf_fix_PaymentRef, tvb, offset, field_len, value);
                    break;
                case 477: /* Field DistribPaymentMethod */
                    proto_tree_add_string(fix_tree, hf_fix_DistribPaymentMethod, tvb, offset, field_len, value);
                    break;
                case 478: /* Field CashDistribCurr */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribCurr, tvb, offset, field_len, value);
                    break;
                case 479: /* Field CommCurrency */
                    proto_tree_add_string(fix_tree, hf_fix_CommCurrency, tvb, offset, field_len, value);
                    break;
                case 480: /* Field CancellationRights */
                    proto_tree_add_string(fix_tree, hf_fix_CancellationRights, tvb, offset, field_len, value);
                    break;
                case 481: /* Field MoneyLaunderingStatus */
                    proto_tree_add_string(fix_tree, hf_fix_MoneyLaunderingStatus, tvb, offset, field_len, value);
                    break;
                case 482: /* Field MailingInst */
                    proto_tree_add_string(fix_tree, hf_fix_MailingInst, tvb, offset, field_len, value);
                    break;
                case 483: /* Field TransBkdTime */
                    proto_tree_add_string(fix_tree, hf_fix_TransBkdTime, tvb, offset, field_len, value);
                    break;
                case 484: /* Field ExecPriceType */
                    proto_tree_add_string(fix_tree, hf_fix_ExecPriceType, tvb, offset, field_len, value);
                    break;
                case 485: /* Field ExecPriceAdjustment */
                    proto_tree_add_string(fix_tree, hf_fix_ExecPriceAdjustment, tvb, offset, field_len, value);
                    break;
                case 486: /* Field DateOfBirth */
                    proto_tree_add_string(fix_tree, hf_fix_DateOfBirth, tvb, offset, field_len, value);
                    break;
                case 487: /* Field TradeReportTransType */
                    proto_tree_add_string(fix_tree, hf_fix_TradeReportTransType, tvb, offset, field_len, value);
                    break;
                case 488: /* Field CardHolderName */
                    proto_tree_add_string(fix_tree, hf_fix_CardHolderName, tvb, offset, field_len, value);
                    break;
                case 489: /* Field CardNumber */
                    proto_tree_add_string(fix_tree, hf_fix_CardNumber, tvb, offset, field_len, value);
                    break;
                case 490: /* Field CardExpDate */
                    proto_tree_add_string(fix_tree, hf_fix_CardExpDate, tvb, offset, field_len, value);
                    break;
                case 491: /* Field CardIssNo */
                    proto_tree_add_string(fix_tree, hf_fix_CardIssNo, tvb, offset, field_len, value);
                    break;
                case 492: /* Field PaymentMethod */
                    proto_tree_add_string(fix_tree, hf_fix_PaymentMethod, tvb, offset, field_len, value);
                    break;
                case 493: /* Field RegistAcctType */
                    proto_tree_add_string(fix_tree, hf_fix_RegistAcctType, tvb, offset, field_len, value);
                    break;
                case 494: /* Field Designation */
                    proto_tree_add_string(fix_tree, hf_fix_Designation, tvb, offset, field_len, value);
                    break;
                case 495: /* Field TaxAdvantageType */
                    proto_tree_add_string(fix_tree, hf_fix_TaxAdvantageType, tvb, offset, field_len, value);
                    break;
                case 496: /* Field RegistRejReasonText */
                    proto_tree_add_string(fix_tree, hf_fix_RegistRejReasonText, tvb, offset, field_len, value);
                    break;
                case 497: /* Field FundRenewWaiv */
                    proto_tree_add_string(fix_tree, hf_fix_FundRenewWaiv, tvb, offset, field_len, value);
                    break;
                case 498: /* Field CashDistribAgentName */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribAgentName, tvb, offset, field_len, value);
                    break;
                case 499: /* Field CashDistribAgentCode */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribAgentCode, tvb, offset, field_len, value);
                    break;
                case 500: /* Field CashDistribAgentAcctNumber */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribAgentAcctNumber, tvb, offset, field_len, value);
                    break;
                case 501: /* Field CashDistribPayRef */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribPayRef, tvb, offset, field_len, value);
                    break;
                case 502: /* Field CashDistribAgentAcctName */
                    proto_tree_add_string(fix_tree, hf_fix_CashDistribAgentAcctName, tvb, offset, field_len, value);
                    break;
                case 503: /* Field CardStartDate */
                    proto_tree_add_string(fix_tree, hf_fix_CardStartDate, tvb, offset, field_len, value);
                    break;
                case 504: /* Field PaymentDate */
                    proto_tree_add_string(fix_tree, hf_fix_PaymentDate, tvb, offset, field_len, value);
                    break;
                case 505: /* Field PaymentRemitterID */
                    proto_tree_add_string(fix_tree, hf_fix_PaymentRemitterID, tvb, offset, field_len, value);
                    break;
                case 506: /* Field RegistStatus */
                    proto_tree_add_string(fix_tree, hf_fix_RegistStatus, tvb, offset, field_len, value);
                    break;
                case 507: /* Field RegistRejReasonCode */
                    proto_tree_add_string(fix_tree, hf_fix_RegistRejReasonCode, tvb, offset, field_len, value);
                    break;
                case 508: /* Field RegistRefID */
                    proto_tree_add_string(fix_tree, hf_fix_RegistRefID, tvb, offset, field_len, value);
                    break;
                case 509: /* Field RegistDetls */
                    proto_tree_add_string(fix_tree, hf_fix_RegistDetls, tvb, offset, field_len, value);
                    break;
                case 510: /* Field NoDistribInsts */
                    proto_tree_add_string(fix_tree, hf_fix_NoDistribInsts, tvb, offset, field_len, value);
                    break;
                case 511: /* Field RegistEmail */
                    proto_tree_add_string(fix_tree, hf_fix_RegistEmail, tvb, offset, field_len, value);
                    break;
                case 512: /* Field DistribPercentage */
                    proto_tree_add_string(fix_tree, hf_fix_DistribPercentage, tvb, offset, field_len, value);
                    break;
                case 513: /* Field RegistID */
                    proto_tree_add_string(fix_tree, hf_fix_RegistID, tvb, offset, field_len, value);
                    break;
                case 514: /* Field RegistTransType */
                    proto_tree_add_string(fix_tree, hf_fix_RegistTransType, tvb, offset, field_len, value);
                    break;
                case 515: /* Field ExecValuationPoint */
                    proto_tree_add_string(fix_tree, hf_fix_ExecValuationPoint, tvb, offset, field_len, value);
                    break;
                case 516: /* Field OrderPercent */
                    proto_tree_add_string(fix_tree, hf_fix_OrderPercent, tvb, offset, field_len, value);
                    break;
                case 517: /* Field OwnershipType */
                    proto_tree_add_string(fix_tree, hf_fix_OwnershipType, tvb, offset, field_len, value);
                    break;
                case 518: /* Field NoContAmts */
                    proto_tree_add_string(fix_tree, hf_fix_NoContAmts, tvb, offset, field_len, value);
                    break;
                case 519: /* Field ContAmtType */
                    proto_tree_add_string(fix_tree, hf_fix_ContAmtType, tvb, offset, field_len, value);
                    break;
                case 520: /* Field ContAmtValue */
                    proto_tree_add_string(fix_tree, hf_fix_ContAmtValue, tvb, offset, field_len, value);
                    break;
                case 521: /* Field ContAmtCurr */
                    proto_tree_add_string(fix_tree, hf_fix_ContAmtCurr, tvb, offset, field_len, value);
                    break;
                case 522: /* Field OwnerType */
                    proto_tree_add_string(fix_tree, hf_fix_OwnerType, tvb, offset, field_len, value);
                    break;
                case 523: /* Field PartySubID */
                    proto_tree_add_string(fix_tree, hf_fix_PartySubID, tvb, offset, field_len, value);
                    break;
                case 524: /* Field NestedPartyID */
                    proto_tree_add_string(fix_tree, hf_fix_NestedPartyID, tvb, offset, field_len, value);
                    break;
                case 525: /* Field NestedPartyIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_NestedPartyIDSource, tvb, offset, field_len, value);
                    break;
                case 526: /* Field SecondaryClOrdID */
                    proto_tree_add_string(fix_tree, hf_fix_SecondaryClOrdID, tvb, offset, field_len, value);
                    break;
                case 527: /* Field SecondaryExecID */
                    proto_tree_add_string(fix_tree, hf_fix_SecondaryExecID, tvb, offset, field_len, value);
                    break;
                case 528: /* Field OrderCapacity */
                    proto_tree_add_string(fix_tree, hf_fix_OrderCapacity, tvb, offset, field_len, value);
                    break;
                case 529: /* Field OrderRestrictions */
                    proto_tree_add_string(fix_tree, hf_fix_OrderRestrictions, tvb, offset, field_len, value);
                    break;
                case 530: /* Field MassCancelRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_MassCancelRequestType, tvb, offset, field_len, value);
                    break;
                case 531: /* Field MassCancelResponse */
                    proto_tree_add_string(fix_tree, hf_fix_MassCancelResponse, tvb, offset, field_len, value);
                    break;
                case 532: /* Field MassCancelRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_MassCancelRejectReason, tvb, offset, field_len, value);
                    break;
                case 533: /* Field TotalAffectedOrders */
                    proto_tree_add_string(fix_tree, hf_fix_TotalAffectedOrders, tvb, offset, field_len, value);
                    break;
                case 534: /* Field NoAffectedOrders */
                    proto_tree_add_string(fix_tree, hf_fix_NoAffectedOrders, tvb, offset, field_len, value);
                    break;
                case 535: /* Field AffectedOrderID */
                    proto_tree_add_string(fix_tree, hf_fix_AffectedOrderID, tvb, offset, field_len, value);
                    break;
                case 536: /* Field AffectedSecondaryOrderID */
                    proto_tree_add_string(fix_tree, hf_fix_AffectedSecondaryOrderID, tvb, offset, field_len, value);
                    break;
                case 537: /* Field QuoteType */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteType, tvb, offset, field_len, value);
                    break;
                case 538: /* Field NestedPartyRole */
                    proto_tree_add_string(fix_tree, hf_fix_NestedPartyRole, tvb, offset, field_len, value);
                    break;
                case 539: /* Field NoNestedPartyIDs */
                    proto_tree_add_string(fix_tree, hf_fix_NoNestedPartyIDs, tvb, offset, field_len, value);
                    break;
                case 540: /* Field TotalAccruedInterestAmt */
                    proto_tree_add_string(fix_tree, hf_fix_TotalAccruedInterestAmt, tvb, offset, field_len, value);
                    break;
                case 541: /* Field MaturityDate */
                    proto_tree_add_string(fix_tree, hf_fix_MaturityDate, tvb, offset, field_len, value);
                    break;
                case 542: /* Field UnderlyingMaturityDate */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingMaturityDate, tvb, offset, field_len, value);
                    break;
                case 543: /* Field InstrRegistry */
                    proto_tree_add_string(fix_tree, hf_fix_InstrRegistry, tvb, offset, field_len, value);
                    break;
                case 544: /* Field CashMargin */
                    proto_tree_add_string(fix_tree, hf_fix_CashMargin, tvb, offset, field_len, value);
                    break;
                case 545: /* Field NestedPartySubID */
                    proto_tree_add_string(fix_tree, hf_fix_NestedPartySubID, tvb, offset, field_len, value);
                    break;
                case 546: /* Field Scope */
                    proto_tree_add_string(fix_tree, hf_fix_Scope, tvb, offset, field_len, value);
                    break;
                case 547: /* Field MDImplicitDelete */
                    proto_tree_add_string(fix_tree, hf_fix_MDImplicitDelete, tvb, offset, field_len, value);
                    break;
                case 548: /* Field CrossID */
                    proto_tree_add_string(fix_tree, hf_fix_CrossID, tvb, offset, field_len, value);
                    break;
                case 549: /* Field CrossType */
                    proto_tree_add_string(fix_tree, hf_fix_CrossType, tvb, offset, field_len, value);
                    break;
                case 550: /* Field CrossPrioritization */
                    proto_tree_add_string(fix_tree, hf_fix_CrossPrioritization, tvb, offset, field_len, value);
                    break;
                case 551: /* Field OrigCrossID */
                    proto_tree_add_string(fix_tree, hf_fix_OrigCrossID, tvb, offset, field_len, value);
                    break;
                case 552: /* Field NoSides */
                    proto_tree_add_string(fix_tree, hf_fix_NoSides, tvb, offset, field_len, value);
                    break;
                case 553: /* Field Username */
                    proto_tree_add_string(fix_tree, hf_fix_Username, tvb, offset, field_len, value);
                    break;
                case 554: /* Field Password */
                    proto_tree_add_string(fix_tree, hf_fix_Password, tvb, offset, field_len, value);
                    break;
                case 555: /* Field NoLegs */
                    proto_tree_add_string(fix_tree, hf_fix_NoLegs, tvb, offset, field_len, value);
                    break;
                case 556: /* Field LegCurrency */
                    proto_tree_add_string(fix_tree, hf_fix_LegCurrency, tvb, offset, field_len, value);
                    break;
                case 557: /* Field TotalNumSecurityTypes */
                    proto_tree_add_string(fix_tree, hf_fix_TotalNumSecurityTypes, tvb, offset, field_len, value);
                    break;
                case 558: /* Field NoSecurityTypes */
                    proto_tree_add_string(fix_tree, hf_fix_NoSecurityTypes, tvb, offset, field_len, value);
                    break;
                case 559: /* Field SecurityListRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityListRequestType, tvb, offset, field_len, value);
                    break;
                case 560: /* Field SecurityRequestResult */
                    proto_tree_add_string(fix_tree, hf_fix_SecurityRequestResult, tvb, offset, field_len, value);
                    break;
                case 561: /* Field RoundLot */
                    proto_tree_add_string(fix_tree, hf_fix_RoundLot, tvb, offset, field_len, value);
                    break;
                case 562: /* Field MinTradeVol */
                    proto_tree_add_string(fix_tree, hf_fix_MinTradeVol, tvb, offset, field_len, value);
                    break;
                case 563: /* Field MultiLegRptTypeReq */
                    proto_tree_add_string(fix_tree, hf_fix_MultiLegRptTypeReq, tvb, offset, field_len, value);
                    break;
                case 564: /* Field LegPositionEffect */
                    proto_tree_add_string(fix_tree, hf_fix_LegPositionEffect, tvb, offset, field_len, value);
                    break;
                case 565: /* Field LegCoveredOrUncovered */
                    proto_tree_add_string(fix_tree, hf_fix_LegCoveredOrUncovered, tvb, offset, field_len, value);
                    break;
                case 566: /* Field LegPrice */
                    proto_tree_add_string(fix_tree, hf_fix_LegPrice, tvb, offset, field_len, value);
                    break;
                case 567: /* Field TradSesStatusRejReason */
                    proto_tree_add_string(fix_tree, hf_fix_TradSesStatusRejReason, tvb, offset, field_len, value);
                    break;
                case 568: /* Field TradeRequestID */
                    proto_tree_add_string(fix_tree, hf_fix_TradeRequestID, tvb, offset, field_len, value);
                    break;
                case 569: /* Field TradeRequestType */
                    proto_tree_add_string(fix_tree, hf_fix_TradeRequestType, tvb, offset, field_len, value);
                    break;
                case 570: /* Field PreviouslyReported */
                    proto_tree_add_string(fix_tree, hf_fix_PreviouslyReported, tvb, offset, field_len, value);
                    break;
                case 571: /* Field TradeReportID */
                    proto_tree_add_string(fix_tree, hf_fix_TradeReportID, tvb, offset, field_len, value);
                    break;
                case 572: /* Field TradeReportRefID */
                    proto_tree_add_string(fix_tree, hf_fix_TradeReportRefID, tvb, offset, field_len, value);
                    break;
                case 573: /* Field MatchStatus */
                    proto_tree_add_string(fix_tree, hf_fix_MatchStatus, tvb, offset, field_len, value);
                    break;
                case 574: /* Field MatchType */
                    proto_tree_add_string(fix_tree, hf_fix_MatchType, tvb, offset, field_len, value);
                    break;
                case 575: /* Field OddLot */
                    proto_tree_add_string(fix_tree, hf_fix_OddLot, tvb, offset, field_len, value);
                    break;
                case 576: /* Field NoClearingInstructions */
                    proto_tree_add_string(fix_tree, hf_fix_NoClearingInstructions, tvb, offset, field_len, value);
                    break;
                case 577: /* Field ClearingInstruction */
                    proto_tree_add_string(fix_tree, hf_fix_ClearingInstruction, tvb, offset, field_len, value);
                    break;
                case 578: /* Field TradeInputSource */
                    proto_tree_add_string(fix_tree, hf_fix_TradeInputSource, tvb, offset, field_len, value);
                    break;
                case 579: /* Field TradeInputDevice */
                    proto_tree_add_string(fix_tree, hf_fix_TradeInputDevice, tvb, offset, field_len, value);
                    break;
                case 580: /* Field NoDates */
                    proto_tree_add_string(fix_tree, hf_fix_NoDates, tvb, offset, field_len, value);
                    break;
                case 581: /* Field AccountType */
                    proto_tree_add_string(fix_tree, hf_fix_AccountType, tvb, offset, field_len, value);
                    break;
                case 582: /* Field CustOrderCapacity */
                    proto_tree_add_string(fix_tree, hf_fix_CustOrderCapacity, tvb, offset, field_len, value);
                    break;
                case 583: /* Field ClOrdLinkID */
                    proto_tree_add_string(fix_tree, hf_fix_ClOrdLinkID, tvb, offset, field_len, value);
                    break;
                case 584: /* Field MassStatusReqID */
                    proto_tree_add_string(fix_tree, hf_fix_MassStatusReqID, tvb, offset, field_len, value);
                    break;
                case 585: /* Field MassStatusReqType */
                    proto_tree_add_string(fix_tree, hf_fix_MassStatusReqType, tvb, offset, field_len, value);
                    break;
                case 586: /* Field OrigOrdModTime */
                    proto_tree_add_string(fix_tree, hf_fix_OrigOrdModTime, tvb, offset, field_len, value);
                    break;
                case 587: /* Field LegSettlmntTyp */
                    proto_tree_add_string(fix_tree, hf_fix_LegSettlmntTyp, tvb, offset, field_len, value);
                    break;
                case 588: /* Field LegFutSettDate */
                    proto_tree_add_string(fix_tree, hf_fix_LegFutSettDate, tvb, offset, field_len, value);
                    break;
                case 589: /* Field DayBookingInst */
                    proto_tree_add_string(fix_tree, hf_fix_DayBookingInst, tvb, offset, field_len, value);
                    break;
                case 590: /* Field BookingUnit */
                    proto_tree_add_string(fix_tree, hf_fix_BookingUnit, tvb, offset, field_len, value);
                    break;
                case 591: /* Field PreallocMethod */
                    proto_tree_add_string(fix_tree, hf_fix_PreallocMethod, tvb, offset, field_len, value);
                    break;
                case 592: /* Field UnderlyingCountryOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingCountryOfIssue, tvb, offset, field_len, value);
                    break;
                case 593: /* Field UnderlyingStateOrProvinceOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingStateOrProvinceOfIssue, tvb, offset, field_len, value);
                    break;
                case 594: /* Field UnderlyingLocaleOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingLocaleOfIssue, tvb, offset, field_len, value);
                    break;
                case 595: /* Field UnderlyingInstrRegistry */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingInstrRegistry, tvb, offset, field_len, value);
                    break;
                case 596: /* Field LegCountryOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_LegCountryOfIssue, tvb, offset, field_len, value);
                    break;
                case 597: /* Field LegStateOrProvinceOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_LegStateOrProvinceOfIssue, tvb, offset, field_len, value);
                    break;
                case 598: /* Field LegLocaleOfIssue */
                    proto_tree_add_string(fix_tree, hf_fix_LegLocaleOfIssue, tvb, offset, field_len, value);
                    break;
                case 599: /* Field LegInstrRegistry */
                    proto_tree_add_string(fix_tree, hf_fix_LegInstrRegistry, tvb, offset, field_len, value);
                    break;
                case 600: /* Field LegSymbol */
                    proto_tree_add_string(fix_tree, hf_fix_LegSymbol, tvb, offset, field_len, value);
                    break;
                case 601: /* Field LegSymbolSfx */
                    proto_tree_add_string(fix_tree, hf_fix_LegSymbolSfx, tvb, offset, field_len, value);
                    break;
                case 602: /* Field LegSecurityID */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityID, tvb, offset, field_len, value);
                    break;
                case 603: /* Field LegSecurityIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityIDSource, tvb, offset, field_len, value);
                    break;
                case 604: /* Field NoLegSecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_NoLegSecurityAltID, tvb, offset, field_len, value);
                    break;
                case 605: /* Field LegSecurityAltID */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityAltID, tvb, offset, field_len, value);
                    break;
                case 606: /* Field LegSecurityAltIDSource */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityAltIDSource, tvb, offset, field_len, value);
                    break;
                case 607: /* Field LegProduct */
                    proto_tree_add_string(fix_tree, hf_fix_LegProduct, tvb, offset, field_len, value);
                    break;
                case 608: /* Field LegCFICode */
                    proto_tree_add_string(fix_tree, hf_fix_LegCFICode, tvb, offset, field_len, value);
                    break;
                case 609: /* Field LegSecurityType */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityType, tvb, offset, field_len, value);
                    break;
                case 610: /* Field LegMaturityMonthYear */
                    proto_tree_add_string(fix_tree, hf_fix_LegMaturityMonthYear, tvb, offset, field_len, value);
                    break;
                case 611: /* Field LegMaturityDate */
                    proto_tree_add_string(fix_tree, hf_fix_LegMaturityDate, tvb, offset, field_len, value);
                    break;
                case 612: /* Field LegStrikePrice */
                    proto_tree_add_string(fix_tree, hf_fix_LegStrikePrice, tvb, offset, field_len, value);
                    break;
                case 613: /* Field LegOptAttribute */
                    proto_tree_add_string(fix_tree, hf_fix_LegOptAttribute, tvb, offset, field_len, value);
                    break;
                case 614: /* Field LegContractMultiplier */
                    proto_tree_add_string(fix_tree, hf_fix_LegContractMultiplier, tvb, offset, field_len, value);
                    break;
                case 615: /* Field LegCouponRate */
                    proto_tree_add_string(fix_tree, hf_fix_LegCouponRate, tvb, offset, field_len, value);
                    break;
                case 616: /* Field LegSecurityExchange */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityExchange, tvb, offset, field_len, value);
                    break;
                case 617: /* Field LegIssuer */
                    proto_tree_add_string(fix_tree, hf_fix_LegIssuer, tvb, offset, field_len, value);
                    break;
                case 618: /* Field EncodedLegIssuerLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedLegIssuerLen, tvb, offset, field_len, value);
                    break;
                case 619: /* Field EncodedLegIssuer */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedLegIssuer, tvb, offset, field_len, value);
                    break;
                case 620: /* Field LegSecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_LegSecurityDesc, tvb, offset, field_len, value);
                    break;
                case 621: /* Field EncodedLegSecurityDescLen */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedLegSecurityDescLen, tvb, offset, field_len, value);
                    break;
                case 622: /* Field EncodedLegSecurityDesc */
                    proto_tree_add_string(fix_tree, hf_fix_EncodedLegSecurityDesc, tvb, offset, field_len, value);
                    break;
                case 623: /* Field LegRatioQty */
                    proto_tree_add_string(fix_tree, hf_fix_LegRatioQty, tvb, offset, field_len, value);
                    break;
                case 624: /* Field LegSide */
                    proto_tree_add_string(fix_tree, hf_fix_LegSide, tvb, offset, field_len, value);
                    break;
                case 625: /* Field TradingSessionSubID */
                    proto_tree_add_string(fix_tree, hf_fix_TradingSessionSubID, tvb, offset, field_len, value);
                    break;
                case 626: /* Field AllocType */
                    proto_tree_add_string(fix_tree, hf_fix_AllocType, tvb, offset, field_len, value);
                    break;
                case 627: /* Field NoHops */
                    proto_tree_add_string(fix_tree, hf_fix_NoHops, tvb, offset, field_len, value);
                    break;
                case 628: /* Field HopCompID */
                    proto_tree_add_string(fix_tree, hf_fix_HopCompID, tvb, offset, field_len, value);
                    break;
                case 629: /* Field HopSendingTime */
                    proto_tree_add_string(fix_tree, hf_fix_HopSendingTime, tvb, offset, field_len, value);
                    break;
                case 630: /* Field HopRefID */
                    proto_tree_add_string(fix_tree, hf_fix_HopRefID, tvb, offset, field_len, value);
                    break;
                case 631: /* Field MidPx */
                    proto_tree_add_string(fix_tree, hf_fix_MidPx, tvb, offset, field_len, value);
                    break;
                case 632: /* Field BidYield */
                    proto_tree_add_string(fix_tree, hf_fix_BidYield, tvb, offset, field_len, value);
                    break;
                case 633: /* Field MidYield */
                    proto_tree_add_string(fix_tree, hf_fix_MidYield, tvb, offset, field_len, value);
                    break;
                case 634: /* Field OfferYield */
                    proto_tree_add_string(fix_tree, hf_fix_OfferYield, tvb, offset, field_len, value);
                    break;
                case 635: /* Field ClearingFeeIndicator */
                    proto_tree_add_string(fix_tree, hf_fix_ClearingFeeIndicator, tvb, offset, field_len, value);
                    break;
                case 636: /* Field WorkingIndicator */
                    proto_tree_add_string(fix_tree, hf_fix_WorkingIndicator, tvb, offset, field_len, value);
                    break;
                case 637: /* Field LegLastPx */
                    proto_tree_add_string(fix_tree, hf_fix_LegLastPx, tvb, offset, field_len, value);
                    break;
                case 638: /* Field PriorityIndicator */
                    proto_tree_add_string(fix_tree, hf_fix_PriorityIndicator, tvb, offset, field_len, value);
                    break;
                case 639: /* Field PriceImprovement */
                    proto_tree_add_string(fix_tree, hf_fix_PriceImprovement, tvb, offset, field_len, value);
                    break;
                case 640: /* Field Price2 */
                    proto_tree_add_string(fix_tree, hf_fix_Price2, tvb, offset, field_len, value);
                    break;
                case 641: /* Field LastForwardPoints2 */
                    proto_tree_add_string(fix_tree, hf_fix_LastForwardPoints2, tvb, offset, field_len, value);
                    break;
                case 642: /* Field BidForwardPoints2 */
                    proto_tree_add_string(fix_tree, hf_fix_BidForwardPoints2, tvb, offset, field_len, value);
                    break;
                case 643: /* Field OfferForwardPoints2 */
                    proto_tree_add_string(fix_tree, hf_fix_OfferForwardPoints2, tvb, offset, field_len, value);
                    break;
                case 644: /* Field RFQReqID */
                    proto_tree_add_string(fix_tree, hf_fix_RFQReqID, tvb, offset, field_len, value);
                    break;
                case 645: /* Field MktBidPx */
                    proto_tree_add_string(fix_tree, hf_fix_MktBidPx, tvb, offset, field_len, value);
                    break;
                case 646: /* Field MktOfferPx */
                    proto_tree_add_string(fix_tree, hf_fix_MktOfferPx, tvb, offset, field_len, value);
                    break;
                case 647: /* Field MinBidSize */
                    proto_tree_add_string(fix_tree, hf_fix_MinBidSize, tvb, offset, field_len, value);
                    break;
                case 648: /* Field MinOfferSize */
                    proto_tree_add_string(fix_tree, hf_fix_MinOfferSize, tvb, offset, field_len, value);
                    break;
                case 649: /* Field QuoteStatusReqID */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteStatusReqID, tvb, offset, field_len, value);
                    break;
                case 650: /* Field LegalConfirm */
                    proto_tree_add_string(fix_tree, hf_fix_LegalConfirm, tvb, offset, field_len, value);
                    break;
                case 651: /* Field UnderlyingLastPx */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingLastPx, tvb, offset, field_len, value);
                    break;
                case 652: /* Field UnderlyingLastQty */
                    proto_tree_add_string(fix_tree, hf_fix_UnderlyingLastQty, tvb, offset, field_len, value);
                    break;
                case 653: /* Field SecDefStatus */
                    proto_tree_add_string(fix_tree, hf_fix_SecDefStatus, tvb, offset, field_len, value);
                    break;
                case 654: /* Field LegRefID */
                    proto_tree_add_string(fix_tree, hf_fix_LegRefID, tvb, offset, field_len, value);
                    break;
                case 655: /* Field ContraLegRefID */
                    proto_tree_add_string(fix_tree, hf_fix_ContraLegRefID, tvb, offset, field_len, value);
                    break;
                case 656: /* Field SettlCurrBidFxRate */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrBidFxRate, tvb, offset, field_len, value);
                    break;
                case 657: /* Field SettlCurrOfferFxRate */
                    proto_tree_add_string(fix_tree, hf_fix_SettlCurrOfferFxRate, tvb, offset, field_len, value);
                    break;
                case 658: /* Field QuoteRequestRejectReason */
                    proto_tree_add_string(fix_tree, hf_fix_QuoteRequestRejectReason, tvb, offset, field_len, value);
                    break;
                case 659: /* Field SideComplianceID */
                    proto_tree_add_string(fix_tree, hf_fix_SideComplianceID, tvb, offset, field_len, value);
                    break;
                default:
                    /* XXX - it could be -1 if the tag isn't a number */
                    proto_tree_add_text(fix_tree, tvb, offset, field_len, "%i: %s", tag, value);
                    break;
            }

            field_offset = offset = ctrla_offset + 1;
            ctrla_offset = tvb_find_guint8(tvb, field_offset, -1, 0x01);

            tag_str = NULL;
        }
    }

    return TRUE;
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fix(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fix_Account,
            { "Account (1)", "fix.Account",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Account", HFILL }
        },
        { &hf_fix_AdvId,
            { "AdvId (2)", "fix.AdvId",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AdvId", HFILL }
        },
        { &hf_fix_AdvRefID,
            { "AdvRefID (3)", "fix.AdvRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AdvRefID", HFILL }
        },
        { &hf_fix_AdvSide,
            { "AdvSide (4)", "fix.AdvSide",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AdvSide", HFILL }
        },
        { &hf_fix_AdvTransType,
            { "AdvTransType (5)", "fix.AdvTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AdvTransType", HFILL }
        },
        { &hf_fix_AvgPx,
            { "AvgPx (6)", "fix.AvgPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AvgPx", HFILL }
        },
        { &hf_fix_BeginSeqNo,
            { "BeginSeqNo (7)", "fix.BeginSeqNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BeginSeqNo", HFILL }
        },
        { &hf_fix_BeginString,
            { "BeginString (8)", "fix.BeginString",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BeginString", HFILL }
        },
        { &hf_fix_BodyLength,
            { "BodyLength (9)", "fix.BodyLength",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BodyLength", HFILL }
        },
        { &hf_fix_CheckSum,
            { "CheckSum (10)", "fix.CheckSum",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CheckSum", HFILL }
        },
        { &hf_fix_ClOrdID,
            { "ClOrdID (11)", "fix.ClOrdID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClOrdID", HFILL }
        },
        { &hf_fix_Commission,
            { "Commission (12)", "fix.Commission",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Commission", HFILL }
        },
        { &hf_fix_CommType,
            { "CommType (13)", "fix.CommType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CommType", HFILL }
        },
        { &hf_fix_CumQty,
            { "CumQty (14)", "fix.CumQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CumQty", HFILL }
        },
        { &hf_fix_Currency,
            { "Currency (15)", "fix.Currency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Currency", HFILL }
        },
        { &hf_fix_EndSeqNo,
            { "EndSeqNo (16)", "fix.EndSeqNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EndSeqNo", HFILL }
        },
        { &hf_fix_ExecID,
            { "ExecID (17)", "fix.ExecID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecID", HFILL }
        },
        { &hf_fix_ExecInst,
            { "ExecInst (18)", "fix.ExecInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecInst", HFILL }
        },
        { &hf_fix_ExecRefID,
            { "ExecRefID (19)", "fix.ExecRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecRefID", HFILL }
        },
        { &hf_fix_ExecTransType,
            { "ExecTransType (20)", "fix.ExecTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecTransType", HFILL }
        },
        { &hf_fix_HandlInst,
            { "HandlInst (21)", "fix.HandlInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HandlInst", HFILL }
        },
        { &hf_fix_SecurityIDSource,
            { "SecurityIDSource (22)", "fix.SecurityIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityIDSource", HFILL }
        },
        { &hf_fix_IOIid,
            { "IOIid (23)", "fix.IOIid",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIid", HFILL }
        },
        { &hf_fix_IOIOthSvc,
            { "IOIOthSvc (24)", "fix.IOIOthSvc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIOthSvc", HFILL }
        },
        { &hf_fix_IOIQltyInd,
            { "IOIQltyInd (25)", "fix.IOIQltyInd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIQltyInd", HFILL }
        },
        { &hf_fix_IOIRefID,
            { "IOIRefID (26)", "fix.IOIRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIRefID", HFILL }
        },
        { &hf_fix_IOIQty,
            { "IOIQty (27)", "fix.IOIQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIQty", HFILL }
        },
        { &hf_fix_IOITransType,
            { "IOITransType (28)", "fix.IOITransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOITransType", HFILL }
        },
        { &hf_fix_LastCapacity,
            { "LastCapacity (29)", "fix.LastCapacity",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastCapacity", HFILL }
        },
        { &hf_fix_LastMkt,
            { "LastMkt (30)", "fix.LastMkt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastMkt", HFILL }
        },
        { &hf_fix_LastPx,
            { "LastPx (31)", "fix.LastPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastPx", HFILL }
        },
        { &hf_fix_LastQty,
            { "LastQty (32)", "fix.LastQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastQty", HFILL }
        },
        { &hf_fix_LinesOfText,
            { "LinesOfText (33)", "fix.LinesOfText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LinesOfText", HFILL }
        },
        { &hf_fix_MsgSeqNum,
            { "MsgSeqNum (34)", "fix.MsgSeqNum",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MsgSeqNum", HFILL }
        },
        { &hf_fix_MsgType,
            { "MsgType (35)", "fix.MsgType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MsgType", HFILL }
        },
        { &hf_fix_NewSeqNo,
            { "NewSeqNo (36)", "fix.NewSeqNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NewSeqNo", HFILL }
        },
        { &hf_fix_OrderID,
            { "OrderID (37)", "fix.OrderID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderID", HFILL }
        },
        { &hf_fix_OrderQty,
            { "OrderQty (38)", "fix.OrderQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderQty", HFILL }
        },
        { &hf_fix_OrdStatus,
            { "OrdStatus (39)", "fix.OrdStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrdStatus", HFILL }
        },
        { &hf_fix_OrdType,
            { "OrdType (40)", "fix.OrdType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrdType", HFILL }
        },
        { &hf_fix_OrigClOrdID,
            { "OrigClOrdID (41)", "fix.OrigClOrdID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrigClOrdID", HFILL }
        },
        { &hf_fix_OrigTime,
            { "OrigTime (42)", "fix.OrigTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrigTime", HFILL }
        },
        { &hf_fix_PossDupFlag,
            { "PossDupFlag (43)", "fix.PossDupFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PossDupFlag", HFILL }
        },
        { &hf_fix_Price,
            { "Price (44)", "fix.Price",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Price", HFILL }
        },
        { &hf_fix_RefSeqNum,
            { "RefSeqNum (45)", "fix.RefSeqNum",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RefSeqNum", HFILL }
        },
        { &hf_fix_RelatdSym,
            { "RelatdSym (46)", "fix.RelatdSym",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RelatdSym", HFILL }
        },
        { &hf_fix_Rule80A,
            { "Rule80A (47)", "fix.Rule80A",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Rule80A", HFILL }
        },
        { &hf_fix_SecurityID,
            { "SecurityID (48)", "fix.SecurityID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityID", HFILL }
        },
        { &hf_fix_SenderCompID,
            { "SenderCompID (49)", "fix.SenderCompID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SenderCompID", HFILL }
        },
        { &hf_fix_SenderSubID,
            { "SenderSubID (50)", "fix.SenderSubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SenderSubID", HFILL }
        },
        { &hf_fix_SendingDate,
            { "SendingDate (51)", "fix.SendingDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SendingDate", HFILL }
        },
        { &hf_fix_SendingTime,
            { "SendingTime (52)", "fix.SendingTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SendingTime", HFILL }
        },
        { &hf_fix_Quantity,
            { "Quantity (53)", "fix.Quantity",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Quantity", HFILL }
        },
        { &hf_fix_Side,
            { "Side (54)", "fix.Side",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Side", HFILL }
        },
        { &hf_fix_Symbol,
            { "Symbol (55)", "fix.Symbol",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Symbol", HFILL }
        },
        { &hf_fix_TargetCompID,
            { "TargetCompID (56)", "fix.TargetCompID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TargetCompID", HFILL }
        },
        { &hf_fix_TargetSubID,
            { "TargetSubID (57)", "fix.TargetSubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TargetSubID", HFILL }
        },
        { &hf_fix_Text,
            { "Text (58)", "fix.Text",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Text", HFILL }
        },
        { &hf_fix_TimeInForce,
            { "TimeInForce (59)", "fix.TimeInForce",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TimeInForce", HFILL }
        },
        { &hf_fix_TransactTime,
            { "TransactTime (60)", "fix.TransactTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TransactTime", HFILL }
        },
        { &hf_fix_Urgency,
            { "Urgency (61)", "fix.Urgency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Urgency", HFILL }
        },
        { &hf_fix_ValidUntilTime,
            { "ValidUntilTime (62)", "fix.ValidUntilTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ValidUntilTime", HFILL }
        },
        { &hf_fix_SettlmntTyp,
            { "SettlmntTyp (63)", "fix.SettlmntTyp",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlmntTyp", HFILL }
        },
        { &hf_fix_FutSettDate,
            { "FutSettDate (64)", "fix.FutSettDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "FutSettDate", HFILL }
        },
        { &hf_fix_SymbolSfx,
            { "SymbolSfx (65)", "fix.SymbolSfx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SymbolSfx", HFILL }
        },
        { &hf_fix_ListID,
            { "ListID (66)", "fix.ListID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListID", HFILL }
        },
        { &hf_fix_ListSeqNo,
            { "ListSeqNo (67)", "fix.ListSeqNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListSeqNo", HFILL }
        },
        { &hf_fix_TotNoOrders,
            { "TotNoOrders (68)", "fix.TotNoOrders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotNoOrders", HFILL }
        },
        { &hf_fix_ListExecInst,
            { "ListExecInst (69)", "fix.ListExecInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListExecInst", HFILL }
        },
        { &hf_fix_AllocID,
            { "AllocID (70)", "fix.AllocID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocID", HFILL }
        },
        { &hf_fix_AllocTransType,
            { "AllocTransType (71)", "fix.AllocTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocTransType", HFILL }
        },
        { &hf_fix_RefAllocID,
            { "RefAllocID (72)", "fix.RefAllocID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RefAllocID", HFILL }
        },
        { &hf_fix_NoOrders,
            { "NoOrders (73)", "fix.NoOrders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoOrders", HFILL }
        },
        { &hf_fix_AvgPrxPrecision,
            { "AvgPrxPrecision (74)", "fix.AvgPrxPrecision",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AvgPrxPrecision", HFILL }
        },
        { &hf_fix_TradeDate,
            { "TradeDate (75)", "fix.TradeDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeDate", HFILL }
        },
        { &hf_fix_ExecBroker,
            { "ExecBroker (76)", "fix.ExecBroker",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecBroker", HFILL }
        },
        { &hf_fix_PositionEffect,
            { "PositionEffect (77)", "fix.PositionEffect",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PositionEffect", HFILL }
        },
        { &hf_fix_NoAllocs,
            { "NoAllocs (78)", "fix.NoAllocs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoAllocs", HFILL }
        },
        { &hf_fix_AllocAccount,
            { "AllocAccount (79)", "fix.AllocAccount",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocAccount", HFILL }
        },
        { &hf_fix_AllocQty,
            { "AllocQty (80)", "fix.AllocQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocQty", HFILL }
        },
        { &hf_fix_ProcessCode,
            { "ProcessCode (81)", "fix.ProcessCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ProcessCode", HFILL }
        },
        { &hf_fix_NoRpts,
            { "NoRpts (82)", "fix.NoRpts",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoRpts", HFILL }
        },
        { &hf_fix_RptSeq,
            { "RptSeq (83)", "fix.RptSeq",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RptSeq", HFILL }
        },
        { &hf_fix_CxlQty,
            { "CxlQty (84)", "fix.CxlQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CxlQty", HFILL }
        },
        { &hf_fix_NoDlvyInst,
            { "NoDlvyInst (85)", "fix.NoDlvyInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoDlvyInst", HFILL }
        },
        { &hf_fix_DlvyInst,
            { "DlvyInst (86)", "fix.DlvyInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DlvyInst", HFILL }
        },
        { &hf_fix_AllocStatus,
            { "AllocStatus (87)", "fix.AllocStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocStatus", HFILL }
        },
        { &hf_fix_AllocRejCode,
            { "AllocRejCode (88)", "fix.AllocRejCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocRejCode", HFILL }
        },
        { &hf_fix_Signature,
            { "Signature (89)", "fix.Signature",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Signature", HFILL }
        },
        { &hf_fix_SecureDataLen,
            { "SecureDataLen (90)", "fix.SecureDataLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecureDataLen", HFILL }
        },
        { &hf_fix_SecureData,
            { "SecureData (91)", "fix.SecureData",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecureData", HFILL }
        },
        { &hf_fix_BrokerOfCredit,
            { "BrokerOfCredit (92)", "fix.BrokerOfCredit",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BrokerOfCredit", HFILL }
        },
        { &hf_fix_SignatureLength,
            { "SignatureLength (93)", "fix.SignatureLength",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SignatureLength", HFILL }
        },
        { &hf_fix_EmailType,
            { "EmailType (94)", "fix.EmailType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EmailType", HFILL }
        },
        { &hf_fix_RawDataLength,
            { "RawDataLength (95)", "fix.RawDataLength",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RawDataLength", HFILL }
        },
        { &hf_fix_RawData,
            { "RawData (96)", "fix.RawData",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RawData", HFILL }
        },
        { &hf_fix_PossResend,
            { "PossResend (97)", "fix.PossResend",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PossResend", HFILL }
        },
        { &hf_fix_EncryptMethod,
            { "EncryptMethod (98)", "fix.EncryptMethod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncryptMethod", HFILL }
        },
        { &hf_fix_StopPx,
            { "StopPx (99)", "fix.StopPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StopPx", HFILL }
        },
        { &hf_fix_ExDestination,
            { "ExDestination (100)", "fix.ExDestination",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExDestination", HFILL }
        },
        { &hf_fix_CxlRejReason,
            { "CxlRejReason (102)", "fix.CxlRejReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CxlRejReason", HFILL }
        },
        { &hf_fix_OrdRejReason,
            { "OrdRejReason (103)", "fix.OrdRejReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrdRejReason", HFILL }
        },
        { &hf_fix_IOIQualifier,
            { "IOIQualifier (104)", "fix.IOIQualifier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOIQualifier", HFILL }
        },
        { &hf_fix_WaveNo,
            { "WaveNo (105)", "fix.WaveNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WaveNo", HFILL }
        },
        { &hf_fix_Issuer,
            { "Issuer (106)", "fix.Issuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Issuer", HFILL }
        },
        { &hf_fix_SecurityDesc,
            { "SecurityDesc (107)", "fix.SecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityDesc", HFILL }
        },
        { &hf_fix_HeartBtInt,
            { "HeartBtInt (108)", "fix.HeartBtInt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HeartBtInt", HFILL }
        },
        { &hf_fix_ClientID,
            { "ClientID (109)", "fix.ClientID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClientID", HFILL }
        },
        { &hf_fix_MinQty,
            { "MinQty (110)", "fix.MinQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MinQty", HFILL }
        },
        { &hf_fix_MaxFloor,
            { "MaxFloor (111)", "fix.MaxFloor",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaxFloor", HFILL }
        },
        { &hf_fix_TestReqID,
            { "TestReqID (112)", "fix.TestReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TestReqID", HFILL }
        },
        { &hf_fix_ReportToExch,
            { "ReportToExch (113)", "fix.ReportToExch",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ReportToExch", HFILL }
        },
        { &hf_fix_LocateReqd,
            { "LocateReqd (114)", "fix.LocateReqd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LocateReqd", HFILL }
        },
        { &hf_fix_OnBehalfOfCompID,
            { "OnBehalfOfCompID (115)", "fix.OnBehalfOfCompID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OnBehalfOfCompID", HFILL }
        },
        { &hf_fix_OnBehalfOfSubID,
            { "OnBehalfOfSubID (116)", "fix.OnBehalfOfSubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OnBehalfOfSubID", HFILL }
        },
        { &hf_fix_QuoteID,
            { "QuoteID (117)", "fix.QuoteID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteID", HFILL }
        },
        { &hf_fix_NetMoney,
            { "NetMoney (118)", "fix.NetMoney",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NetMoney", HFILL }
        },
        { &hf_fix_SettlCurrAmt,
            { "SettlCurrAmt (119)", "fix.SettlCurrAmt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrAmt", HFILL }
        },
        { &hf_fix_SettlCurrency,
            { "SettlCurrency (120)", "fix.SettlCurrency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrency", HFILL }
        },
        { &hf_fix_ForexReq,
            { "ForexReq (121)", "fix.ForexReq",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ForexReq", HFILL }
        },
        { &hf_fix_OrigSendingTime,
            { "OrigSendingTime (122)", "fix.OrigSendingTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrigSendingTime", HFILL }
        },
        { &hf_fix_GapFillFlag,
            { "GapFillFlag (123)", "fix.GapFillFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "GapFillFlag", HFILL }
        },
        { &hf_fix_NoExecs,
            { "NoExecs (124)", "fix.NoExecs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoExecs", HFILL }
        },
        { &hf_fix_CxlType,
            { "CxlType (125)", "fix.CxlType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CxlType", HFILL }
        },
        { &hf_fix_ExpireTime,
            { "ExpireTime (126)", "fix.ExpireTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExpireTime", HFILL }
        },
        { &hf_fix_DKReason,
            { "DKReason (127)", "fix.DKReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DKReason", HFILL }
        },
        { &hf_fix_DeliverToCompID,
            { "DeliverToCompID (128)", "fix.DeliverToCompID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DeliverToCompID", HFILL }
        },
        { &hf_fix_DeliverToSubID,
            { "DeliverToSubID (129)", "fix.DeliverToSubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DeliverToSubID", HFILL }
        },
        { &hf_fix_IOINaturalFlag,
            { "IOINaturalFlag (130)", "fix.IOINaturalFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IOINaturalFlag", HFILL }
        },
        { &hf_fix_QuoteReqID,
            { "QuoteReqID (131)", "fix.QuoteReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteReqID", HFILL }
        },
        { &hf_fix_BidPx,
            { "BidPx (132)", "fix.BidPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidPx", HFILL }
        },
        { &hf_fix_OfferPx,
            { "OfferPx (133)", "fix.OfferPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferPx", HFILL }
        },
        { &hf_fix_BidSize,
            { "BidSize (134)", "fix.BidSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidSize", HFILL }
        },
        { &hf_fix_OfferSize,
            { "OfferSize (135)", "fix.OfferSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferSize", HFILL }
        },
        { &hf_fix_NoMiscFees,
            { "NoMiscFees (136)", "fix.NoMiscFees",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoMiscFees", HFILL }
        },
        { &hf_fix_MiscFeeAmt,
            { "MiscFeeAmt (137)", "fix.MiscFeeAmt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MiscFeeAmt", HFILL }
        },
        { &hf_fix_MiscFeeCurr,
            { "MiscFeeCurr (138)", "fix.MiscFeeCurr",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MiscFeeCurr", HFILL }
        },
        { &hf_fix_MiscFeeType,
            { "MiscFeeType (139)", "fix.MiscFeeType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MiscFeeType", HFILL }
        },
        { &hf_fix_PrevClosePx,
            { "PrevClosePx (140)", "fix.PrevClosePx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PrevClosePx", HFILL }
        },
        { &hf_fix_ResetSeqNumFlag,
            { "ResetSeqNumFlag (141)", "fix.ResetSeqNumFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ResetSeqNumFlag", HFILL }
        },
        { &hf_fix_SenderLocationID,
            { "SenderLocationID (142)", "fix.SenderLocationID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SenderLocationID", HFILL }
        },
        { &hf_fix_TargetLocationID,
            { "TargetLocationID (143)", "fix.TargetLocationID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TargetLocationID", HFILL }
        },
        { &hf_fix_OnBehalfOfLocationID,
            { "OnBehalfOfLocationID (144)", "fix.OnBehalfOfLocationID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OnBehalfOfLocationID", HFILL }
        },
        { &hf_fix_DeliverToLocationID,
            { "DeliverToLocationID (145)", "fix.DeliverToLocationID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DeliverToLocationID", HFILL }
        },
        { &hf_fix_NoRelatedSym,
            { "NoRelatedSym (146)", "fix.NoRelatedSym",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoRelatedSym", HFILL }
        },
        { &hf_fix_Subject,
            { "Subject (147)", "fix.Subject",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Subject", HFILL }
        },
        { &hf_fix_Headline,
            { "Headline (148)", "fix.Headline",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Headline", HFILL }
        },
        { &hf_fix_URLLink,
            { "URLLink (149)", "fix.URLLink",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "URLLink", HFILL }
        },
        { &hf_fix_ExecType,
            { "ExecType (150)", "fix.ExecType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecType", HFILL }
        },
        { &hf_fix_LeavesQty,
            { "LeavesQty (151)", "fix.LeavesQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LeavesQty", HFILL }
        },
        { &hf_fix_CashOrderQty,
            { "CashOrderQty (152)", "fix.CashOrderQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashOrderQty", HFILL }
        },
        { &hf_fix_AllocAvgPx,
            { "AllocAvgPx (153)", "fix.AllocAvgPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocAvgPx", HFILL }
        },
        { &hf_fix_AllocNetMoney,
            { "AllocNetMoney (154)", "fix.AllocNetMoney",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocNetMoney", HFILL }
        },
        { &hf_fix_SettlCurrFxRate,
            { "SettlCurrFxRate (155)", "fix.SettlCurrFxRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrFxRate", HFILL }
        },
        { &hf_fix_SettlCurrFxRateCalc,
            { "SettlCurrFxRateCalc (156)", "fix.SettlCurrFxRateCalc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrFxRateCalc", HFILL }
        },
        { &hf_fix_NumDaysInterest,
            { "NumDaysInterest (157)", "fix.NumDaysInterest",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NumDaysInterest", HFILL }
        },
        { &hf_fix_AccruedInterestRate,
            { "AccruedInterestRate (158)", "fix.AccruedInterestRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AccruedInterestRate", HFILL }
        },
        { &hf_fix_AccruedInterestAmt,
            { "AccruedInterestAmt (159)", "fix.AccruedInterestAmt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AccruedInterestAmt", HFILL }
        },
        { &hf_fix_SettlInstMode,
            { "SettlInstMode (160)", "fix.SettlInstMode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstMode", HFILL }
        },
        { &hf_fix_AllocText,
            { "AllocText (161)", "fix.AllocText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocText", HFILL }
        },
        { &hf_fix_SettlInstID,
            { "SettlInstID (162)", "fix.SettlInstID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstID", HFILL }
        },
        { &hf_fix_SettlInstTransType,
            { "SettlInstTransType (163)", "fix.SettlInstTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstTransType", HFILL }
        },
        { &hf_fix_EmailThreadID,
            { "EmailThreadID (164)", "fix.EmailThreadID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EmailThreadID", HFILL }
        },
        { &hf_fix_SettlInstSource,
            { "SettlInstSource (165)", "fix.SettlInstSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstSource", HFILL }
        },
        { &hf_fix_SettlLocation,
            { "SettlLocation (166)", "fix.SettlLocation",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlLocation", HFILL }
        },
        { &hf_fix_SecurityType,
            { "SecurityType (167)", "fix.SecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityType", HFILL }
        },
        { &hf_fix_EffectiveTime,
            { "EffectiveTime (168)", "fix.EffectiveTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EffectiveTime", HFILL }
        },
        { &hf_fix_StandInstDbType,
            { "StandInstDbType (169)", "fix.StandInstDbType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StandInstDbType", HFILL }
        },
        { &hf_fix_StandInstDbName,
            { "StandInstDbName (170)", "fix.StandInstDbName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StandInstDbName", HFILL }
        },
        { &hf_fix_StandInstDbID,
            { "StandInstDbID (171)", "fix.StandInstDbID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StandInstDbID", HFILL }
        },
        { &hf_fix_SettlDeliveryType,
            { "SettlDeliveryType (172)", "fix.SettlDeliveryType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlDeliveryType", HFILL }
        },
        { &hf_fix_SettlDepositoryCode,
            { "SettlDepositoryCode (173)", "fix.SettlDepositoryCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlDepositoryCode", HFILL }
        },
        { &hf_fix_SettlBrkrCode,
            { "SettlBrkrCode (174)", "fix.SettlBrkrCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlBrkrCode", HFILL }
        },
        { &hf_fix_SettlInstCode,
            { "SettlInstCode (175)", "fix.SettlInstCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstCode", HFILL }
        },
        { &hf_fix_SecuritySettlAgentName,
            { "SecuritySettlAgentName (176)", "fix.SecuritySettlAgentName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentName", HFILL }
        },
        { &hf_fix_SecuritySettlAgentCode,
            { "SecuritySettlAgentCode (177)", "fix.SecuritySettlAgentCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentCode", HFILL }
        },
        { &hf_fix_SecuritySettlAgentAcctNum,
            { "SecuritySettlAgentAcctNum (178)", "fix.SecuritySettlAgentAcctNum",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentAcctNum", HFILL }
        },
        { &hf_fix_SecuritySettlAgentAcctName,
            { "SecuritySettlAgentAcctName (179)", "fix.SecuritySettlAgentAcctName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentAcctName", HFILL }
        },
        { &hf_fix_SecuritySettlAgentContactName,
            { "SecuritySettlAgentContactName (180)", "fix.SecuritySettlAgentContactName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentContactName", HFILL }
        },
        { &hf_fix_SecuritySettlAgentContactPhone,
            { "SecuritySettlAgentContactPhone (181)", "fix.SecuritySettlAgentContactPhone",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecuritySettlAgentContactPhone", HFILL }
        },
        { &hf_fix_CashSettlAgentName,
            { "CashSettlAgentName (182)", "fix.CashSettlAgentName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentName", HFILL }
        },
        { &hf_fix_CashSettlAgentCode,
            { "CashSettlAgentCode (183)", "fix.CashSettlAgentCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentCode", HFILL }
        },
        { &hf_fix_CashSettlAgentAcctNum,
            { "CashSettlAgentAcctNum (184)", "fix.CashSettlAgentAcctNum",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentAcctNum", HFILL }
        },
        { &hf_fix_CashSettlAgentAcctName,
            { "CashSettlAgentAcctName (185)", "fix.CashSettlAgentAcctName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentAcctName", HFILL }
        },
        { &hf_fix_CashSettlAgentContactName,
            { "CashSettlAgentContactName (186)", "fix.CashSettlAgentContactName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentContactName", HFILL }
        },
        { &hf_fix_CashSettlAgentContactPhone,
            { "CashSettlAgentContactPhone (187)", "fix.CashSettlAgentContactPhone",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashSettlAgentContactPhone", HFILL }
        },
        { &hf_fix_BidSpotRate,
            { "BidSpotRate (188)", "fix.BidSpotRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidSpotRate", HFILL }
        },
        { &hf_fix_BidForwardPoints,
            { "BidForwardPoints (189)", "fix.BidForwardPoints",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidForwardPoints", HFILL }
        },
        { &hf_fix_OfferSpotRate,
            { "OfferSpotRate (190)", "fix.OfferSpotRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferSpotRate", HFILL }
        },
        { &hf_fix_OfferForwardPoints,
            { "OfferForwardPoints (191)", "fix.OfferForwardPoints",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferForwardPoints", HFILL }
        },
        { &hf_fix_OrderQty2,
            { "OrderQty2 (192)", "fix.OrderQty2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderQty2", HFILL }
        },
        { &hf_fix_FutSettDate2,
            { "FutSettDate2 (193)", "fix.FutSettDate2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "FutSettDate2", HFILL }
        },
        { &hf_fix_LastSpotRate,
            { "LastSpotRate (194)", "fix.LastSpotRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastSpotRate", HFILL }
        },
        { &hf_fix_LastForwardPoints,
            { "LastForwardPoints (195)", "fix.LastForwardPoints",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastForwardPoints", HFILL }
        },
        { &hf_fix_AllocLinkID,
            { "AllocLinkID (196)", "fix.AllocLinkID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocLinkID", HFILL }
        },
        { &hf_fix_AllocLinkType,
            { "AllocLinkType (197)", "fix.AllocLinkType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocLinkType", HFILL }
        },
        { &hf_fix_SecondaryOrderID,
            { "SecondaryOrderID (198)", "fix.SecondaryOrderID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecondaryOrderID", HFILL }
        },
        { &hf_fix_NoIOIQualifiers,
            { "NoIOIQualifiers (199)", "fix.NoIOIQualifiers",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoIOIQualifiers", HFILL }
        },
        { &hf_fix_MaturityMonthYear,
            { "MaturityMonthYear (200)", "fix.MaturityMonthYear",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaturityMonthYear", HFILL }
        },
        { &hf_fix_PutOrCall,
            { "PutOrCall (201)", "fix.PutOrCall",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PutOrCall", HFILL }
        },
        { &hf_fix_StrikePrice,
            { "StrikePrice (202)", "fix.StrikePrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StrikePrice", HFILL }
        },
        { &hf_fix_CoveredOrUncovered,
            { "CoveredOrUncovered (203)", "fix.CoveredOrUncovered",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CoveredOrUncovered", HFILL }
        },
        { &hf_fix_CustomerOrFirm,
            { "CustomerOrFirm (204)", "fix.CustomerOrFirm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CustomerOrFirm", HFILL }
        },
        { &hf_fix_MaturityDay,
            { "MaturityDay (205)", "fix.MaturityDay",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaturityDay", HFILL }
        },
        { &hf_fix_OptAttribute,
            { "OptAttribute (206)", "fix.OptAttribute",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OptAttribute", HFILL }
        },
        { &hf_fix_SecurityExchange,
            { "SecurityExchange (207)", "fix.SecurityExchange",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityExchange", HFILL }
        },
        { &hf_fix_NotifyBrokerOfCredit,
            { "NotifyBrokerOfCredit (208)", "fix.NotifyBrokerOfCredit",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NotifyBrokerOfCredit", HFILL }
        },
        { &hf_fix_AllocHandlInst,
            { "AllocHandlInst (209)", "fix.AllocHandlInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocHandlInst", HFILL }
        },
        { &hf_fix_MaxShow,
            { "MaxShow (210)", "fix.MaxShow",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaxShow", HFILL }
        },
        { &hf_fix_PegDifference,
            { "PegDifference (211)", "fix.PegDifference",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PegDifference", HFILL }
        },
        { &hf_fix_XmlDataLen,
            { "XmlDataLen (212)", "fix.XmlDataLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "XmlDataLen", HFILL }
        },
        { &hf_fix_XmlData,
            { "XmlData (213)", "fix.XmlData",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "XmlData", HFILL }
        },
        { &hf_fix_SettlInstRefID,
            { "SettlInstRefID (214)", "fix.SettlInstRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlInstRefID", HFILL }
        },
        { &hf_fix_NoRoutingIDs,
            { "NoRoutingIDs (215)", "fix.NoRoutingIDs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoRoutingIDs", HFILL }
        },
        { &hf_fix_RoutingType,
            { "RoutingType (216)", "fix.RoutingType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RoutingType", HFILL }
        },
        { &hf_fix_RoutingID,
            { "RoutingID (217)", "fix.RoutingID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RoutingID", HFILL }
        },
        { &hf_fix_Spread,
            { "Spread (218)", "fix.Spread",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Spread", HFILL }
        },
        { &hf_fix_Benchmark,
            { "Benchmark (219)", "fix.Benchmark",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Benchmark", HFILL }
        },
        { &hf_fix_BenchmarkCurveCurrency,
            { "BenchmarkCurveCurrency (220)", "fix.BenchmarkCurveCurrency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BenchmarkCurveCurrency", HFILL }
        },
        { &hf_fix_BenchmarkCurveName,
            { "BenchmarkCurveName (221)", "fix.BenchmarkCurveName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BenchmarkCurveName", HFILL }
        },
        { &hf_fix_BenchmarkCurvePoint,
            { "BenchmarkCurvePoint (222)", "fix.BenchmarkCurvePoint",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BenchmarkCurvePoint", HFILL }
        },
        { &hf_fix_CouponRate,
            { "CouponRate (223)", "fix.CouponRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CouponRate", HFILL }
        },
        { &hf_fix_CouponPaymentDate,
            { "CouponPaymentDate (224)", "fix.CouponPaymentDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CouponPaymentDate", HFILL }
        },
        { &hf_fix_IssueDate,
            { "IssueDate (225)", "fix.IssueDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IssueDate", HFILL }
        },
        { &hf_fix_RepurchaseTerm,
            { "RepurchaseTerm (226)", "fix.RepurchaseTerm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RepurchaseTerm", HFILL }
        },
        { &hf_fix_RepurchaseRate,
            { "RepurchaseRate (227)", "fix.RepurchaseRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RepurchaseRate", HFILL }
        },
        { &hf_fix_Factor,
            { "Factor (228)", "fix.Factor",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Factor", HFILL }
        },
        { &hf_fix_TradeOriginationDate,
            { "TradeOriginationDate (229)", "fix.TradeOriginationDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeOriginationDate", HFILL }
        },
        { &hf_fix_ExDate,
            { "ExDate (230)", "fix.ExDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExDate", HFILL }
        },
        { &hf_fix_ContractMultiplier,
            { "ContractMultiplier (231)", "fix.ContractMultiplier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContractMultiplier", HFILL }
        },
        { &hf_fix_NoStipulations,
            { "NoStipulations (232)", "fix.NoStipulations",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoStipulations", HFILL }
        },
        { &hf_fix_StipulationType,
            { "StipulationType (233)", "fix.StipulationType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StipulationType", HFILL }
        },
        { &hf_fix_StipulationValue,
            { "StipulationValue (234)", "fix.StipulationValue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StipulationValue", HFILL }
        },
        { &hf_fix_YieldType,
            { "YieldType (235)", "fix.YieldType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "YieldType", HFILL }
        },
        { &hf_fix_Yield,
            { "Yield (236)", "fix.Yield",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Yield", HFILL }
        },
        { &hf_fix_TotalTakedown,
            { "TotalTakedown (237)", "fix.TotalTakedown",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalTakedown", HFILL }
        },
        { &hf_fix_Concession,
            { "Concession (238)", "fix.Concession",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Concession", HFILL }
        },
        { &hf_fix_RepoCollateralSecurityType,
            { "RepoCollateralSecurityType (239)", "fix.RepoCollateralSecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RepoCollateralSecurityType", HFILL }
        },
        { &hf_fix_RedemptionDate,
            { "RedemptionDate (240)", "fix.RedemptionDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RedemptionDate", HFILL }
        },
        { &hf_fix_UnderlyingCouponPaymentDate,
            { "UnderlyingCouponPaymentDate (241)", "fix.UnderlyingCouponPaymentDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingCouponPaymentDate", HFILL }
        },
        { &hf_fix_UnderlyingIssueDate,
            { "UnderlyingIssueDate (242)", "fix.UnderlyingIssueDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingIssueDate", HFILL }
        },
        { &hf_fix_UnderlyingRepoCollateralSecurityType,
            { "UnderlyingRepoCollateralSecurityType (243)", "fix.UnderlyingRepoCollateralSecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingRepoCollateralSecurityType", HFILL }
        },
        { &hf_fix_UnderlyingRepurchaseTerm,
            { "UnderlyingRepurchaseTerm (244)", "fix.UnderlyingRepurchaseTerm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingRepurchaseTerm", HFILL }
        },
        { &hf_fix_UnderlyingRepurchaseRate,
            { "UnderlyingRepurchaseRate (245)", "fix.UnderlyingRepurchaseRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingRepurchaseRate", HFILL }
        },
        { &hf_fix_UnderlyingFactor,
            { "UnderlyingFactor (246)", "fix.UnderlyingFactor",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingFactor", HFILL }
        },
        { &hf_fix_UnderlyingRedemptionDate,
            { "UnderlyingRedemptionDate (247)", "fix.UnderlyingRedemptionDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingRedemptionDate", HFILL }
        },
        { &hf_fix_LegCouponPaymentDate,
            { "LegCouponPaymentDate (248)", "fix.LegCouponPaymentDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCouponPaymentDate", HFILL }
        },
        { &hf_fix_LegIssueDate,
            { "LegIssueDate (249)", "fix.LegIssueDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegIssueDate", HFILL }
        },
        { &hf_fix_LegRepoCollateralSecurityType,
            { "LegRepoCollateralSecurityType (250)", "fix.LegRepoCollateralSecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRepoCollateralSecurityType", HFILL }
        },
        { &hf_fix_LegRepurchaseTerm,
            { "LegRepurchaseTerm (251)", "fix.LegRepurchaseTerm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRepurchaseTerm", HFILL }
        },
        { &hf_fix_LegRepurchaseRate,
            { "LegRepurchaseRate (252)", "fix.LegRepurchaseRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRepurchaseRate", HFILL }
        },
        { &hf_fix_LegFactor,
            { "LegFactor (253)", "fix.LegFactor",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegFactor", HFILL }
        },
        { &hf_fix_LegRedemptionDate,
            { "LegRedemptionDate (254)", "fix.LegRedemptionDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRedemptionDate", HFILL }
        },
        { &hf_fix_CreditRating,
            { "CreditRating (255)", "fix.CreditRating",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CreditRating", HFILL }
        },
        { &hf_fix_UnderlyingCreditRating,
            { "UnderlyingCreditRating (256)", "fix.UnderlyingCreditRating",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingCreditRating", HFILL }
        },
        { &hf_fix_LegCreditRating,
            { "LegCreditRating (257)", "fix.LegCreditRating",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCreditRating", HFILL }
        },
        { &hf_fix_TradedFlatSwitch,
            { "TradedFlatSwitch (258)", "fix.TradedFlatSwitch",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradedFlatSwitch", HFILL }
        },
        { &hf_fix_BasisFeatureDate,
            { "BasisFeatureDate (259)", "fix.BasisFeatureDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BasisFeatureDate", HFILL }
        },
        { &hf_fix_BasisFeaturePrice,
            { "BasisFeaturePrice (260)", "fix.BasisFeaturePrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BasisFeaturePrice", HFILL }
        },
        { &hf_fix_ReservedAllocated,
            { "ReservedAllocated (261)", "fix.ReservedAllocated",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ReservedAllocated", HFILL }
        },
        { &hf_fix_MDReqID,
            { "MDReqID (262)", "fix.MDReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDReqID", HFILL }
        },
        { &hf_fix_SubscriptionRequestType,
            { "SubscriptionRequestType (263)", "fix.SubscriptionRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SubscriptionRequestType", HFILL }
        },
        { &hf_fix_MarketDepth,
            { "MarketDepth (264)", "fix.MarketDepth",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MarketDepth", HFILL }
        },
        { &hf_fix_MDUpdateType,
            { "MDUpdateType (265)", "fix.MDUpdateType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDUpdateType", HFILL }
        },
        { &hf_fix_AggregatedBook,
            { "AggregatedBook (266)", "fix.AggregatedBook",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AggregatedBook", HFILL }
        },
        { &hf_fix_NoMDEntryTypes,
            { "NoMDEntryTypes (267)", "fix.NoMDEntryTypes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoMDEntryTypes", HFILL }
        },
        { &hf_fix_NoMDEntries,
            { "NoMDEntries (268)", "fix.NoMDEntries",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoMDEntries", HFILL }
        },
        { &hf_fix_MDEntryType,
            { "MDEntryType (269)", "fix.MDEntryType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryType", HFILL }
        },
        { &hf_fix_MDEntryPx,
            { "MDEntryPx (270)", "fix.MDEntryPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryPx", HFILL }
        },
        { &hf_fix_MDEntrySize,
            { "MDEntrySize (271)", "fix.MDEntrySize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntrySize", HFILL }
        },
        { &hf_fix_MDEntryDate,
            { "MDEntryDate (272)", "fix.MDEntryDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryDate", HFILL }
        },
        { &hf_fix_MDEntryTime,
            { "MDEntryTime (273)", "fix.MDEntryTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryTime", HFILL }
        },
        { &hf_fix_TickDirection,
            { "TickDirection (274)", "fix.TickDirection",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TickDirection", HFILL }
        },
        { &hf_fix_MDMkt,
            { "MDMkt (275)", "fix.MDMkt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDMkt", HFILL }
        },
        { &hf_fix_QuoteCondition,
            { "QuoteCondition (276)", "fix.QuoteCondition",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteCondition", HFILL }
        },
        { &hf_fix_TradeCondition,
            { "TradeCondition (277)", "fix.TradeCondition",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeCondition", HFILL }
        },
        { &hf_fix_MDEntryID,
            { "MDEntryID (278)", "fix.MDEntryID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryID", HFILL }
        },
        { &hf_fix_MDUpdateAction,
            { "MDUpdateAction (279)", "fix.MDUpdateAction",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDUpdateAction", HFILL }
        },
        { &hf_fix_MDEntryRefID,
            { "MDEntryRefID (280)", "fix.MDEntryRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryRefID", HFILL }
        },
        { &hf_fix_MDReqRejReason,
            { "MDReqRejReason (281)", "fix.MDReqRejReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDReqRejReason", HFILL }
        },
        { &hf_fix_MDEntryOriginator,
            { "MDEntryOriginator (282)", "fix.MDEntryOriginator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryOriginator", HFILL }
        },
        { &hf_fix_LocationID,
            { "LocationID (283)", "fix.LocationID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LocationID", HFILL }
        },
        { &hf_fix_DeskID,
            { "DeskID (284)", "fix.DeskID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DeskID", HFILL }
        },
        { &hf_fix_DeleteReason,
            { "DeleteReason (285)", "fix.DeleteReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DeleteReason", HFILL }
        },
        { &hf_fix_OpenCloseSettleFlag,
            { "OpenCloseSettleFlag (286)", "fix.OpenCloseSettleFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OpenCloseSettleFlag", HFILL }
        },
        { &hf_fix_SellerDays,
            { "SellerDays (287)", "fix.SellerDays",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SellerDays", HFILL }
        },
        { &hf_fix_MDEntryBuyer,
            { "MDEntryBuyer (288)", "fix.MDEntryBuyer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryBuyer", HFILL }
        },
        { &hf_fix_MDEntrySeller,
            { "MDEntrySeller (289)", "fix.MDEntrySeller",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntrySeller", HFILL }
        },
        { &hf_fix_MDEntryPositionNo,
            { "MDEntryPositionNo (290)", "fix.MDEntryPositionNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDEntryPositionNo", HFILL }
        },
        { &hf_fix_FinancialStatus,
            { "FinancialStatus (291)", "fix.FinancialStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "FinancialStatus", HFILL }
        },
        { &hf_fix_CorporateAction,
            { "CorporateAction (292)", "fix.CorporateAction",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CorporateAction", HFILL }
        },
        { &hf_fix_DefBidSize,
            { "DefBidSize (293)", "fix.DefBidSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DefBidSize", HFILL }
        },
        { &hf_fix_DefOfferSize,
            { "DefOfferSize (294)", "fix.DefOfferSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DefOfferSize", HFILL }
        },
        { &hf_fix_NoQuoteEntries,
            { "NoQuoteEntries (295)", "fix.NoQuoteEntries",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoQuoteEntries", HFILL }
        },
        { &hf_fix_NoQuoteSets,
            { "NoQuoteSets (296)", "fix.NoQuoteSets",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoQuoteSets", HFILL }
        },
        { &hf_fix_QuoteStatus,
            { "QuoteStatus (297)", "fix.QuoteStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteStatus", HFILL }
        },
        { &hf_fix_QuoteCancelType,
            { "QuoteCancelType (298)", "fix.QuoteCancelType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteCancelType", HFILL }
        },
        { &hf_fix_QuoteEntryID,
            { "QuoteEntryID (299)", "fix.QuoteEntryID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteEntryID", HFILL }
        },
        { &hf_fix_QuoteRejectReason,
            { "QuoteRejectReason (300)", "fix.QuoteRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteRejectReason", HFILL }
        },
        { &hf_fix_QuoteResponseLevel,
            { "QuoteResponseLevel (301)", "fix.QuoteResponseLevel",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteResponseLevel", HFILL }
        },
        { &hf_fix_QuoteSetID,
            { "QuoteSetID (302)", "fix.QuoteSetID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteSetID", HFILL }
        },
        { &hf_fix_QuoteRequestType,
            { "QuoteRequestType (303)", "fix.QuoteRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteRequestType", HFILL }
        },
        { &hf_fix_TotQuoteEntries,
            { "TotQuoteEntries (304)", "fix.TotQuoteEntries",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotQuoteEntries", HFILL }
        },
        { &hf_fix_UnderlyingSecurityIDSource,
            { "UnderlyingSecurityIDSource (305)", "fix.UnderlyingSecurityIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityIDSource", HFILL }
        },
        { &hf_fix_UnderlyingIssuer,
            { "UnderlyingIssuer (306)", "fix.UnderlyingIssuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingIssuer", HFILL }
        },
        { &hf_fix_UnderlyingSecurityDesc,
            { "UnderlyingSecurityDesc (307)", "fix.UnderlyingSecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityDesc", HFILL }
        },
        { &hf_fix_UnderlyingSecurityExchange,
            { "UnderlyingSecurityExchange (308)", "fix.UnderlyingSecurityExchange",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityExchange", HFILL }
        },
        { &hf_fix_UnderlyingSecurityID,
            { "UnderlyingSecurityID (309)", "fix.UnderlyingSecurityID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityID", HFILL }
        },
        { &hf_fix_UnderlyingSecurityType,
            { "UnderlyingSecurityType (310)", "fix.UnderlyingSecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityType", HFILL }
        },
        { &hf_fix_UnderlyingSymbol,
            { "UnderlyingSymbol (311)", "fix.UnderlyingSymbol",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSymbol", HFILL }
        },
        { &hf_fix_UnderlyingSymbolSfx,
            { "UnderlyingSymbolSfx (312)", "fix.UnderlyingSymbolSfx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSymbolSfx", HFILL }
        },
        { &hf_fix_UnderlyingMaturityMonthYear,
            { "UnderlyingMaturityMonthYear (313)", "fix.UnderlyingMaturityMonthYear",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingMaturityMonthYear", HFILL }
        },
        { &hf_fix_UnderlyingMaturityDay,
            { "UnderlyingMaturityDay (314)", "fix.UnderlyingMaturityDay",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingMaturityDay", HFILL }
        },
        { &hf_fix_UnderlyingPutOrCall,
            { "UnderlyingPutOrCall (315)", "fix.UnderlyingPutOrCall",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingPutOrCall", HFILL }
        },
        { &hf_fix_UnderlyingStrikePrice,
            { "UnderlyingStrikePrice (316)", "fix.UnderlyingStrikePrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingStrikePrice", HFILL }
        },
        { &hf_fix_UnderlyingOptAttribute,
            { "UnderlyingOptAttribute (317)", "fix.UnderlyingOptAttribute",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingOptAttribute", HFILL }
        },
        { &hf_fix_Underlying,
            { "Underlying (318)", "fix.Underlying",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Underlying", HFILL }
        },
        { &hf_fix_RatioQty,
            { "RatioQty (319)", "fix.RatioQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RatioQty", HFILL }
        },
        { &hf_fix_SecurityReqID,
            { "SecurityReqID (320)", "fix.SecurityReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityReqID", HFILL }
        },
        { &hf_fix_SecurityRequestType,
            { "SecurityRequestType (321)", "fix.SecurityRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityRequestType", HFILL }
        },
        { &hf_fix_SecurityResponseID,
            { "SecurityResponseID (322)", "fix.SecurityResponseID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityResponseID", HFILL }
        },
        { &hf_fix_SecurityResponseType,
            { "SecurityResponseType (323)", "fix.SecurityResponseType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityResponseType", HFILL }
        },
        { &hf_fix_SecurityStatusReqID,
            { "SecurityStatusReqID (324)", "fix.SecurityStatusReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityStatusReqID", HFILL }
        },
        { &hf_fix_UnsolicitedIndicator,
            { "UnsolicitedIndicator (325)", "fix.UnsolicitedIndicator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnsolicitedIndicator", HFILL }
        },
        { &hf_fix_SecurityTradingStatus,
            { "SecurityTradingStatus (326)", "fix.SecurityTradingStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityTradingStatus", HFILL }
        },
        { &hf_fix_HaltReason,
            { "HaltReason (327)", "fix.HaltReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HaltReason", HFILL }
        },
        { &hf_fix_InViewOfCommon,
            { "InViewOfCommon (328)", "fix.InViewOfCommon",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "InViewOfCommon", HFILL }
        },
        { &hf_fix_DueToRelated,
            { "DueToRelated (329)", "fix.DueToRelated",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DueToRelated", HFILL }
        },
        { &hf_fix_BuyVolume,
            { "BuyVolume (330)", "fix.BuyVolume",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BuyVolume", HFILL }
        },
        { &hf_fix_SellVolume,
            { "SellVolume (331)", "fix.SellVolume",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SellVolume", HFILL }
        },
        { &hf_fix_HighPx,
            { "HighPx (332)", "fix.HighPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HighPx", HFILL }
        },
        { &hf_fix_LowPx,
            { "LowPx (333)", "fix.LowPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LowPx", HFILL }
        },
        { &hf_fix_Adjustment,
            { "Adjustment (334)", "fix.Adjustment",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Adjustment", HFILL }
        },
        { &hf_fix_TradSesReqID,
            { "TradSesReqID (335)", "fix.TradSesReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesReqID", HFILL }
        },
        { &hf_fix_TradingSessionID,
            { "TradingSessionID (336)", "fix.TradingSessionID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradingSessionID", HFILL }
        },
        { &hf_fix_ContraTrader,
            { "ContraTrader (337)", "fix.ContraTrader",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContraTrader", HFILL }
        },
        { &hf_fix_TradSesMethod,
            { "TradSesMethod (338)", "fix.TradSesMethod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesMethod", HFILL }
        },
        { &hf_fix_TradSesMode,
            { "TradSesMode (339)", "fix.TradSesMode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesMode", HFILL }
        },
        { &hf_fix_TradSesStatus,
            { "TradSesStatus (340)", "fix.TradSesStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesStatus", HFILL }
        },
        { &hf_fix_TradSesStartTime,
            { "TradSesStartTime (341)", "fix.TradSesStartTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesStartTime", HFILL }
        },
        { &hf_fix_TradSesOpenTime,
            { "TradSesOpenTime (342)", "fix.TradSesOpenTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesOpenTime", HFILL }
        },
        { &hf_fix_TradSesPreCloseTime,
            { "TradSesPreCloseTime (343)", "fix.TradSesPreCloseTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesPreCloseTime", HFILL }
        },
        { &hf_fix_TradSesCloseTime,
            { "TradSesCloseTime (344)", "fix.TradSesCloseTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesCloseTime", HFILL }
        },
        { &hf_fix_TradSesEndTime,
            { "TradSesEndTime (345)", "fix.TradSesEndTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesEndTime", HFILL }
        },
        { &hf_fix_NumberOfOrders,
            { "NumberOfOrders (346)", "fix.NumberOfOrders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NumberOfOrders", HFILL }
        },
        { &hf_fix_MessageEncoding,
            { "MessageEncoding (347)", "fix.MessageEncoding",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MessageEncoding", HFILL }
        },
        { &hf_fix_EncodedIssuerLen,
            { "EncodedIssuerLen (348)", "fix.EncodedIssuerLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedIssuerLen", HFILL }
        },
        { &hf_fix_EncodedIssuer,
            { "EncodedIssuer (349)", "fix.EncodedIssuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedIssuer", HFILL }
        },
        { &hf_fix_EncodedSecurityDescLen,
            { "EncodedSecurityDescLen (350)", "fix.EncodedSecurityDescLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedSecurityDescLen", HFILL }
        },
        { &hf_fix_EncodedSecurityDesc,
            { "EncodedSecurityDesc (351)", "fix.EncodedSecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedSecurityDesc", HFILL }
        },
        { &hf_fix_EncodedListExecInstLen,
            { "EncodedListExecInstLen (352)", "fix.EncodedListExecInstLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedListExecInstLen", HFILL }
        },
        { &hf_fix_EncodedListExecInst,
            { "EncodedListExecInst (353)", "fix.EncodedListExecInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedListExecInst", HFILL }
        },
        { &hf_fix_EncodedTextLen,
            { "EncodedTextLen (354)", "fix.EncodedTextLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedTextLen", HFILL }
        },
        { &hf_fix_EncodedText,
            { "EncodedText (355)", "fix.EncodedText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedText", HFILL }
        },
        { &hf_fix_EncodedSubjectLen,
            { "EncodedSubjectLen (356)", "fix.EncodedSubjectLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedSubjectLen", HFILL }
        },
        { &hf_fix_EncodedSubject,
            { "EncodedSubject (357)", "fix.EncodedSubject",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedSubject", HFILL }
        },
        { &hf_fix_EncodedHeadlineLen,
            { "EncodedHeadlineLen (358)", "fix.EncodedHeadlineLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedHeadlineLen", HFILL }
        },
        { &hf_fix_EncodedHeadline,
            { "EncodedHeadline (359)", "fix.EncodedHeadline",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedHeadline", HFILL }
        },
        { &hf_fix_EncodedAllocTextLen,
            { "EncodedAllocTextLen (360)", "fix.EncodedAllocTextLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedAllocTextLen", HFILL }
        },
        { &hf_fix_EncodedAllocText,
            { "EncodedAllocText (361)", "fix.EncodedAllocText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedAllocText", HFILL }
        },
        { &hf_fix_EncodedUnderlyingIssuerLen,
            { "EncodedUnderlyingIssuerLen (362)", "fix.EncodedUnderlyingIssuerLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedUnderlyingIssuerLen", HFILL }
        },
        { &hf_fix_EncodedUnderlyingIssuer,
            { "EncodedUnderlyingIssuer (363)", "fix.EncodedUnderlyingIssuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedUnderlyingIssuer", HFILL }
        },
        { &hf_fix_EncodedUnderlyingSecurityDescLen,
            { "EncodedUnderlyingSecurityDescLen (364)", "fix.EncodedUnderlyingSecurityDescLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedUnderlyingSecurityDescLen", HFILL }
        },
        { &hf_fix_EncodedUnderlyingSecurityDesc,
            { "EncodedUnderlyingSecurityDesc (365)", "fix.EncodedUnderlyingSecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedUnderlyingSecurityDesc", HFILL }
        },
        { &hf_fix_AllocPrice,
            { "AllocPrice (366)", "fix.AllocPrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocPrice", HFILL }
        },
        { &hf_fix_QuoteSetValidUntilTime,
            { "QuoteSetValidUntilTime (367)", "fix.QuoteSetValidUntilTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteSetValidUntilTime", HFILL }
        },
        { &hf_fix_QuoteEntryRejectReason,
            { "QuoteEntryRejectReason (368)", "fix.QuoteEntryRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteEntryRejectReason", HFILL }
        },
        { &hf_fix_LastMsgSeqNumProcessed,
            { "LastMsgSeqNumProcessed (369)", "fix.LastMsgSeqNumProcessed",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastMsgSeqNumProcessed", HFILL }
        },
        { &hf_fix_OnBehalfOfSendingTime,
            { "OnBehalfOfSendingTime (370)", "fix.OnBehalfOfSendingTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OnBehalfOfSendingTime", HFILL }
        },
        { &hf_fix_RefTagID,
            { "RefTagID (371)", "fix.RefTagID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RefTagID", HFILL }
        },
        { &hf_fix_RefMsgType,
            { "RefMsgType (372)", "fix.RefMsgType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RefMsgType", HFILL }
        },
        { &hf_fix_SessionRejectReason,
            { "SessionRejectReason (373)", "fix.SessionRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SessionRejectReason", HFILL }
        },
        { &hf_fix_BidRequestTransType,
            { "BidRequestTransType (374)", "fix.BidRequestTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidRequestTransType", HFILL }
        },
        { &hf_fix_ContraBroker,
            { "ContraBroker (375)", "fix.ContraBroker",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContraBroker", HFILL }
        },
        { &hf_fix_ComplianceID,
            { "ComplianceID (376)", "fix.ComplianceID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ComplianceID", HFILL }
        },
        { &hf_fix_SolicitedFlag,
            { "SolicitedFlag (377)", "fix.SolicitedFlag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SolicitedFlag", HFILL }
        },
        { &hf_fix_ExecRestatementReason,
            { "ExecRestatementReason (378)", "fix.ExecRestatementReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecRestatementReason", HFILL }
        },
        { &hf_fix_BusinessRejectRefID,
            { "BusinessRejectRefID (379)", "fix.BusinessRejectRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BusinessRejectRefID", HFILL }
        },
        { &hf_fix_BusinessRejectReason,
            { "BusinessRejectReason (380)", "fix.BusinessRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BusinessRejectReason", HFILL }
        },
        { &hf_fix_GrossTradeAmt,
            { "GrossTradeAmt (381)", "fix.GrossTradeAmt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "GrossTradeAmt", HFILL }
        },
        { &hf_fix_NoContraBrokers,
            { "NoContraBrokers (382)", "fix.NoContraBrokers",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoContraBrokers", HFILL }
        },
        { &hf_fix_MaxMessageSize,
            { "MaxMessageSize (383)", "fix.MaxMessageSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaxMessageSize", HFILL }
        },
        { &hf_fix_NoMsgTypes,
            { "NoMsgTypes (384)", "fix.NoMsgTypes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoMsgTypes", HFILL }
        },
        { &hf_fix_MsgDirection,
            { "MsgDirection (385)", "fix.MsgDirection",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MsgDirection", HFILL }
        },
        { &hf_fix_NoTradingSessions,
            { "NoTradingSessions (386)", "fix.NoTradingSessions",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoTradingSessions", HFILL }
        },
        { &hf_fix_TotalVolumeTraded,
            { "TotalVolumeTraded (387)", "fix.TotalVolumeTraded",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalVolumeTraded", HFILL }
        },
        { &hf_fix_DiscretionInst,
            { "DiscretionInst (388)", "fix.DiscretionInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DiscretionInst", HFILL }
        },
        { &hf_fix_DiscretionOffset,
            { "DiscretionOffset (389)", "fix.DiscretionOffset",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DiscretionOffset", HFILL }
        },
        { &hf_fix_BidID,
            { "BidID (390)", "fix.BidID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidID", HFILL }
        },
        { &hf_fix_ClientBidID,
            { "ClientBidID (391)", "fix.ClientBidID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClientBidID", HFILL }
        },
        { &hf_fix_ListName,
            { "ListName (392)", "fix.ListName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListName", HFILL }
        },
        { &hf_fix_TotalNumSecurities,
            { "TotalNumSecurities (393)", "fix.TotalNumSecurities",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalNumSecurities", HFILL }
        },
        { &hf_fix_BidType,
            { "BidType (394)", "fix.BidType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidType", HFILL }
        },
        { &hf_fix_NumTickets,
            { "NumTickets (395)", "fix.NumTickets",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NumTickets", HFILL }
        },
        { &hf_fix_SideValue1,
            { "SideValue1 (396)", "fix.SideValue1",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SideValue1", HFILL }
        },
        { &hf_fix_SideValue2,
            { "SideValue2 (397)", "fix.SideValue2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SideValue2", HFILL }
        },
        { &hf_fix_NoBidDescriptors,
            { "NoBidDescriptors (398)", "fix.NoBidDescriptors",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoBidDescriptors", HFILL }
        },
        { &hf_fix_BidDescriptorType,
            { "BidDescriptorType (399)", "fix.BidDescriptorType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidDescriptorType", HFILL }
        },
        { &hf_fix_BidDescriptor,
            { "BidDescriptor (400)", "fix.BidDescriptor",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidDescriptor", HFILL }
        },
        { &hf_fix_SideValueInd,
            { "SideValueInd (401)", "fix.SideValueInd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SideValueInd", HFILL }
        },
        { &hf_fix_LiquidityPctLow,
            { "LiquidityPctLow (402)", "fix.LiquidityPctLow",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LiquidityPctLow", HFILL }
        },
        { &hf_fix_LiquidityPctHigh,
            { "LiquidityPctHigh (403)", "fix.LiquidityPctHigh",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LiquidityPctHigh", HFILL }
        },
        { &hf_fix_LiquidityValue,
            { "LiquidityValue (404)", "fix.LiquidityValue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LiquidityValue", HFILL }
        },
        { &hf_fix_EFPTrackingError,
            { "EFPTrackingError (405)", "fix.EFPTrackingError",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EFPTrackingError", HFILL }
        },
        { &hf_fix_FairValue,
            { "FairValue (406)", "fix.FairValue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "FairValue", HFILL }
        },
        { &hf_fix_OutsideIndexPct,
            { "OutsideIndexPct (407)", "fix.OutsideIndexPct",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OutsideIndexPct", HFILL }
        },
        { &hf_fix_ValueOfFutures,
            { "ValueOfFutures (408)", "fix.ValueOfFutures",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ValueOfFutures", HFILL }
        },
        { &hf_fix_LiquidityIndType,
            { "LiquidityIndType (409)", "fix.LiquidityIndType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LiquidityIndType", HFILL }
        },
        { &hf_fix_WtAverageLiquidity,
            { "WtAverageLiquidity (410)", "fix.WtAverageLiquidity",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WtAverageLiquidity", HFILL }
        },
        { &hf_fix_ExchangeForPhysical,
            { "ExchangeForPhysical (411)", "fix.ExchangeForPhysical",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExchangeForPhysical", HFILL }
        },
        { &hf_fix_OutMainCntryUIndex,
            { "OutMainCntryUIndex (412)", "fix.OutMainCntryUIndex",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OutMainCntryUIndex", HFILL }
        },
        { &hf_fix_CrossPercent,
            { "CrossPercent (413)", "fix.CrossPercent",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CrossPercent", HFILL }
        },
        { &hf_fix_ProgRptReqs,
            { "ProgRptReqs (414)", "fix.ProgRptReqs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ProgRptReqs", HFILL }
        },
        { &hf_fix_ProgPeriodInterval,
            { "ProgPeriodInterval (415)", "fix.ProgPeriodInterval",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ProgPeriodInterval", HFILL }
        },
        { &hf_fix_IncTaxInd,
            { "IncTaxInd (416)", "fix.IncTaxInd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IncTaxInd", HFILL }
        },
        { &hf_fix_NumBidders,
            { "NumBidders (417)", "fix.NumBidders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NumBidders", HFILL }
        },
        { &hf_fix_TradeType,
            { "TradeType (418)", "fix.TradeType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeType", HFILL }
        },
        { &hf_fix_BasisPxType,
            { "BasisPxType (419)", "fix.BasisPxType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BasisPxType", HFILL }
        },
        { &hf_fix_NoBidComponents,
            { "NoBidComponents (420)", "fix.NoBidComponents",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoBidComponents", HFILL }
        },
        { &hf_fix_Country,
            { "Country (421)", "fix.Country",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Country", HFILL }
        },
        { &hf_fix_TotNoStrikes,
            { "TotNoStrikes (422)", "fix.TotNoStrikes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotNoStrikes", HFILL }
        },
        { &hf_fix_PriceType,
            { "PriceType (423)", "fix.PriceType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PriceType", HFILL }
        },
        { &hf_fix_DayOrderQty,
            { "DayOrderQty (424)", "fix.DayOrderQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DayOrderQty", HFILL }
        },
        { &hf_fix_DayCumQty,
            { "DayCumQty (425)", "fix.DayCumQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DayCumQty", HFILL }
        },
        { &hf_fix_DayAvgPx,
            { "DayAvgPx (426)", "fix.DayAvgPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DayAvgPx", HFILL }
        },
        { &hf_fix_GTBookingInst,
            { "GTBookingInst (427)", "fix.GTBookingInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "GTBookingInst", HFILL }
        },
        { &hf_fix_NoStrikes,
            { "NoStrikes (428)", "fix.NoStrikes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoStrikes", HFILL }
        },
        { &hf_fix_ListStatusType,
            { "ListStatusType (429)", "fix.ListStatusType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListStatusType", HFILL }
        },
        { &hf_fix_NetGrossInd,
            { "NetGrossInd (430)", "fix.NetGrossInd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NetGrossInd", HFILL }
        },
        { &hf_fix_ListOrderStatus,
            { "ListOrderStatus (431)", "fix.ListOrderStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListOrderStatus", HFILL }
        },
        { &hf_fix_ExpireDate,
            { "ExpireDate (432)", "fix.ExpireDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExpireDate", HFILL }
        },
        { &hf_fix_ListExecInstType,
            { "ListExecInstType (433)", "fix.ListExecInstType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListExecInstType", HFILL }
        },
        { &hf_fix_CxlRejResponseTo,
            { "CxlRejResponseTo (434)", "fix.CxlRejResponseTo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CxlRejResponseTo", HFILL }
        },
        { &hf_fix_UnderlyingCouponRate,
            { "UnderlyingCouponRate (435)", "fix.UnderlyingCouponRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingCouponRate", HFILL }
        },
        { &hf_fix_UnderlyingContractMultiplier,
            { "UnderlyingContractMultiplier (436)", "fix.UnderlyingContractMultiplier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingContractMultiplier", HFILL }
        },
        { &hf_fix_ContraTradeQty,
            { "ContraTradeQty (437)", "fix.ContraTradeQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContraTradeQty", HFILL }
        },
        { &hf_fix_ContraTradeTime,
            { "ContraTradeTime (438)", "fix.ContraTradeTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContraTradeTime", HFILL }
        },
        { &hf_fix_ClearingFirm,
            { "ClearingFirm (439)", "fix.ClearingFirm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClearingFirm", HFILL }
        },
        { &hf_fix_ClearingAccount,
            { "ClearingAccount (440)", "fix.ClearingAccount",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClearingAccount", HFILL }
        },
        { &hf_fix_LiquidityNumSecurities,
            { "LiquidityNumSecurities (441)", "fix.LiquidityNumSecurities",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LiquidityNumSecurities", HFILL }
        },
        { &hf_fix_MultiLegReportingType,
            { "MultiLegReportingType (442)", "fix.MultiLegReportingType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MultiLegReportingType", HFILL }
        },
        { &hf_fix_StrikeTime,
            { "StrikeTime (443)", "fix.StrikeTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StrikeTime", HFILL }
        },
        { &hf_fix_ListStatusText,
            { "ListStatusText (444)", "fix.ListStatusText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ListStatusText", HFILL }
        },
        { &hf_fix_EncodedListStatusTextLen,
            { "EncodedListStatusTextLen (445)", "fix.EncodedListStatusTextLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedListStatusTextLen", HFILL }
        },
        { &hf_fix_EncodedListStatusText,
            { "EncodedListStatusText (446)", "fix.EncodedListStatusText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedListStatusText", HFILL }
        },
        { &hf_fix_PartyIDSource,
            { "PartyIDSource (447)", "fix.PartyIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PartyIDSource", HFILL }
        },
        { &hf_fix_PartyID,
            { "PartyID (448)", "fix.PartyID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PartyID", HFILL }
        },
        { &hf_fix_TotalVolumeTradedDate,
            { "TotalVolumeTradedDate (449)", "fix.TotalVolumeTradedDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalVolumeTradedDate", HFILL }
        },
        { &hf_fix_TotalVolumeTradedTime,
            { "TotalVolumeTradedTime (450)", "fix.TotalVolumeTradedTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalVolumeTradedTime", HFILL }
        },
        { &hf_fix_NetChgPrevDay,
            { "NetChgPrevDay (451)", "fix.NetChgPrevDay",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NetChgPrevDay", HFILL }
        },
        { &hf_fix_PartyRole,
            { "PartyRole (452)", "fix.PartyRole",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PartyRole", HFILL }
        },
        { &hf_fix_NoPartyIDs,
            { "NoPartyIDs (453)", "fix.NoPartyIDs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoPartyIDs", HFILL }
        },
        { &hf_fix_NoSecurityAltID,
            { "NoSecurityAltID (454)", "fix.NoSecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoSecurityAltID", HFILL }
        },
        { &hf_fix_SecurityAltID,
            { "SecurityAltID (455)", "fix.SecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityAltID", HFILL }
        },
        { &hf_fix_SecurityAltIDSource,
            { "SecurityAltIDSource (456)", "fix.SecurityAltIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityAltIDSource", HFILL }
        },
        { &hf_fix_NoUnderlyingSecurityAltID,
            { "NoUnderlyingSecurityAltID (457)", "fix.NoUnderlyingSecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoUnderlyingSecurityAltID", HFILL }
        },
        { &hf_fix_UnderlyingSecurityAltID,
            { "UnderlyingSecurityAltID (458)", "fix.UnderlyingSecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityAltID", HFILL }
        },
        { &hf_fix_UnderlyingSecurityAltIDSource,
            { "UnderlyingSecurityAltIDSource (459)", "fix.UnderlyingSecurityAltIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingSecurityAltIDSource", HFILL }
        },
        { &hf_fix_Product,
            { "Product (460)", "fix.Product",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Product", HFILL }
        },
        { &hf_fix_CFICode,
            { "CFICode (461)", "fix.CFICode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CFICode", HFILL }
        },
        { &hf_fix_UnderlyingProduct,
            { "UnderlyingProduct (462)", "fix.UnderlyingProduct",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingProduct", HFILL }
        },
        { &hf_fix_UnderlyingCFICode,
            { "UnderlyingCFICode (463)", "fix.UnderlyingCFICode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingCFICode", HFILL }
        },
        { &hf_fix_TestMessageIndicator,
            { "TestMessageIndicator (464)", "fix.TestMessageIndicator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TestMessageIndicator", HFILL }
        },
        { &hf_fix_QuantityType,
            { "QuantityType (465)", "fix.QuantityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuantityType", HFILL }
        },
        { &hf_fix_BookingRefID,
            { "BookingRefID (466)", "fix.BookingRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BookingRefID", HFILL }
        },
        { &hf_fix_IndividualAllocID,
            { "IndividualAllocID (467)", "fix.IndividualAllocID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "IndividualAllocID", HFILL }
        },
        { &hf_fix_RoundingDirection,
            { "RoundingDirection (468)", "fix.RoundingDirection",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RoundingDirection", HFILL }
        },
        { &hf_fix_RoundingModulus,
            { "RoundingModulus (469)", "fix.RoundingModulus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RoundingModulus", HFILL }
        },
        { &hf_fix_CountryOfIssue,
            { "CountryOfIssue (470)", "fix.CountryOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CountryOfIssue", HFILL }
        },
        { &hf_fix_StateOrProvinceOfIssue,
            { "StateOrProvinceOfIssue (471)", "fix.StateOrProvinceOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "StateOrProvinceOfIssue", HFILL }
        },
        { &hf_fix_LocaleOfIssue,
            { "LocaleOfIssue (472)", "fix.LocaleOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LocaleOfIssue", HFILL }
        },
        { &hf_fix_NoRegistDtls,
            { "NoRegistDtls (473)", "fix.NoRegistDtls",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoRegistDtls", HFILL }
        },
        { &hf_fix_MailingDtls,
            { "MailingDtls (474)", "fix.MailingDtls",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MailingDtls", HFILL }
        },
        { &hf_fix_InvestorCountryOfResidence,
            { "InvestorCountryOfResidence (475)", "fix.InvestorCountryOfResidence",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "InvestorCountryOfResidence", HFILL }
        },
        { &hf_fix_PaymentRef,
            { "PaymentRef (476)", "fix.PaymentRef",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PaymentRef", HFILL }
        },
        { &hf_fix_DistribPaymentMethod,
            { "DistribPaymentMethod (477)", "fix.DistribPaymentMethod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DistribPaymentMethod", HFILL }
        },
        { &hf_fix_CashDistribCurr,
            { "CashDistribCurr (478)", "fix.CashDistribCurr",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribCurr", HFILL }
        },
        { &hf_fix_CommCurrency,
            { "CommCurrency (479)", "fix.CommCurrency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CommCurrency", HFILL }
        },
        { &hf_fix_CancellationRights,
            { "CancellationRights (480)", "fix.CancellationRights",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CancellationRights", HFILL }
        },
        { &hf_fix_MoneyLaunderingStatus,
            { "MoneyLaunderingStatus (481)", "fix.MoneyLaunderingStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MoneyLaunderingStatus", HFILL }
        },
        { &hf_fix_MailingInst,
            { "MailingInst (482)", "fix.MailingInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MailingInst", HFILL }
        },
        { &hf_fix_TransBkdTime,
            { "TransBkdTime (483)", "fix.TransBkdTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TransBkdTime", HFILL }
        },
        { &hf_fix_ExecPriceType,
            { "ExecPriceType (484)", "fix.ExecPriceType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecPriceType", HFILL }
        },
        { &hf_fix_ExecPriceAdjustment,
            { "ExecPriceAdjustment (485)", "fix.ExecPriceAdjustment",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecPriceAdjustment", HFILL }
        },
        { &hf_fix_DateOfBirth,
            { "DateOfBirth (486)", "fix.DateOfBirth",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DateOfBirth", HFILL }
        },
        { &hf_fix_TradeReportTransType,
            { "TradeReportTransType (487)", "fix.TradeReportTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeReportTransType", HFILL }
        },
        { &hf_fix_CardHolderName,
            { "CardHolderName (488)", "fix.CardHolderName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CardHolderName", HFILL }
        },
        { &hf_fix_CardNumber,
            { "CardNumber (489)", "fix.CardNumber",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CardNumber", HFILL }
        },
        { &hf_fix_CardExpDate,
            { "CardExpDate (490)", "fix.CardExpDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CardExpDate", HFILL }
        },
        { &hf_fix_CardIssNo,
            { "CardIssNo (491)", "fix.CardIssNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CardIssNo", HFILL }
        },
        { &hf_fix_PaymentMethod,
            { "PaymentMethod (492)", "fix.PaymentMethod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PaymentMethod", HFILL }
        },
        { &hf_fix_RegistAcctType,
            { "RegistAcctType (493)", "fix.RegistAcctType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistAcctType", HFILL }
        },
        { &hf_fix_Designation,
            { "Designation (494)", "fix.Designation",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Designation", HFILL }
        },
        { &hf_fix_TaxAdvantageType,
            { "TaxAdvantageType (495)", "fix.TaxAdvantageType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TaxAdvantageType", HFILL }
        },
        { &hf_fix_RegistRejReasonText,
            { "RegistRejReasonText (496)", "fix.RegistRejReasonText",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistRejReasonText", HFILL }
        },
        { &hf_fix_FundRenewWaiv,
            { "FundRenewWaiv (497)", "fix.FundRenewWaiv",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "FundRenewWaiv", HFILL }
        },
        { &hf_fix_CashDistribAgentName,
            { "CashDistribAgentName (498)", "fix.CashDistribAgentName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribAgentName", HFILL }
        },
        { &hf_fix_CashDistribAgentCode,
            { "CashDistribAgentCode (499)", "fix.CashDistribAgentCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribAgentCode", HFILL }
        },
        { &hf_fix_CashDistribAgentAcctNumber,
            { "CashDistribAgentAcctNumber (500)", "fix.CashDistribAgentAcctNumber",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribAgentAcctNumber", HFILL }
        },
        { &hf_fix_CashDistribPayRef,
            { "CashDistribPayRef (501)", "fix.CashDistribPayRef",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribPayRef", HFILL }
        },
        { &hf_fix_CashDistribAgentAcctName,
            { "CashDistribAgentAcctName (502)", "fix.CashDistribAgentAcctName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashDistribAgentAcctName", HFILL }
        },
        { &hf_fix_CardStartDate,
            { "CardStartDate (503)", "fix.CardStartDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CardStartDate", HFILL }
        },
        { &hf_fix_PaymentDate,
            { "PaymentDate (504)", "fix.PaymentDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PaymentDate", HFILL }
        },
        { &hf_fix_PaymentRemitterID,
            { "PaymentRemitterID (505)", "fix.PaymentRemitterID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PaymentRemitterID", HFILL }
        },
        { &hf_fix_RegistStatus,
            { "RegistStatus (506)", "fix.RegistStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistStatus", HFILL }
        },
        { &hf_fix_RegistRejReasonCode,
            { "RegistRejReasonCode (507)", "fix.RegistRejReasonCode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistRejReasonCode", HFILL }
        },
        { &hf_fix_RegistRefID,
            { "RegistRefID (508)", "fix.RegistRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistRefID", HFILL }
        },
        { &hf_fix_RegistDetls,
            { "RegistDetls (509)", "fix.RegistDetls",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistDetls", HFILL }
        },
        { &hf_fix_NoDistribInsts,
            { "NoDistribInsts (510)", "fix.NoDistribInsts",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoDistribInsts", HFILL }
        },
        { &hf_fix_RegistEmail,
            { "RegistEmail (511)", "fix.RegistEmail",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistEmail", HFILL }
        },
        { &hf_fix_DistribPercentage,
            { "DistribPercentage (512)", "fix.DistribPercentage",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DistribPercentage", HFILL }
        },
        { &hf_fix_RegistID,
            { "RegistID (513)", "fix.RegistID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistID", HFILL }
        },
        { &hf_fix_RegistTransType,
            { "RegistTransType (514)", "fix.RegistTransType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RegistTransType", HFILL }
        },
        { &hf_fix_ExecValuationPoint,
            { "ExecValuationPoint (515)", "fix.ExecValuationPoint",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ExecValuationPoint", HFILL }
        },
        { &hf_fix_OrderPercent,
            { "OrderPercent (516)", "fix.OrderPercent",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderPercent", HFILL }
        },
        { &hf_fix_OwnershipType,
            { "OwnershipType (517)", "fix.OwnershipType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OwnershipType", HFILL }
        },
        { &hf_fix_NoContAmts,
            { "NoContAmts (518)", "fix.NoContAmts",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoContAmts", HFILL }
        },
        { &hf_fix_ContAmtType,
            { "ContAmtType (519)", "fix.ContAmtType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContAmtType", HFILL }
        },
        { &hf_fix_ContAmtValue,
            { "ContAmtValue (520)", "fix.ContAmtValue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContAmtValue", HFILL }
        },
        { &hf_fix_ContAmtCurr,
            { "ContAmtCurr (521)", "fix.ContAmtCurr",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContAmtCurr", HFILL }
        },
        { &hf_fix_OwnerType,
            { "OwnerType (522)", "fix.OwnerType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OwnerType", HFILL }
        },
        { &hf_fix_PartySubID,
            { "PartySubID (523)", "fix.PartySubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PartySubID", HFILL }
        },
        { &hf_fix_NestedPartyID,
            { "NestedPartyID (524)", "fix.NestedPartyID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NestedPartyID", HFILL }
        },
        { &hf_fix_NestedPartyIDSource,
            { "NestedPartyIDSource (525)", "fix.NestedPartyIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NestedPartyIDSource", HFILL }
        },
        { &hf_fix_SecondaryClOrdID,
            { "SecondaryClOrdID (526)", "fix.SecondaryClOrdID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecondaryClOrdID", HFILL }
        },
        { &hf_fix_SecondaryExecID,
            { "SecondaryExecID (527)", "fix.SecondaryExecID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecondaryExecID", HFILL }
        },
        { &hf_fix_OrderCapacity,
            { "OrderCapacity (528)", "fix.OrderCapacity",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderCapacity", HFILL }
        },
        { &hf_fix_OrderRestrictions,
            { "OrderRestrictions (529)", "fix.OrderRestrictions",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrderRestrictions", HFILL }
        },
        { &hf_fix_MassCancelRequestType,
            { "MassCancelRequestType (530)", "fix.MassCancelRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MassCancelRequestType", HFILL }
        },
        { &hf_fix_MassCancelResponse,
            { "MassCancelResponse (531)", "fix.MassCancelResponse",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MassCancelResponse", HFILL }
        },
        { &hf_fix_MassCancelRejectReason,
            { "MassCancelRejectReason (532)", "fix.MassCancelRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MassCancelRejectReason", HFILL }
        },
        { &hf_fix_TotalAffectedOrders,
            { "TotalAffectedOrders (533)", "fix.TotalAffectedOrders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalAffectedOrders", HFILL }
        },
        { &hf_fix_NoAffectedOrders,
            { "NoAffectedOrders (534)", "fix.NoAffectedOrders",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoAffectedOrders", HFILL }
        },
        { &hf_fix_AffectedOrderID,
            { "AffectedOrderID (535)", "fix.AffectedOrderID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AffectedOrderID", HFILL }
        },
        { &hf_fix_AffectedSecondaryOrderID,
            { "AffectedSecondaryOrderID (536)", "fix.AffectedSecondaryOrderID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AffectedSecondaryOrderID", HFILL }
        },
        { &hf_fix_QuoteType,
            { "QuoteType (537)", "fix.QuoteType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteType", HFILL }
        },
        { &hf_fix_NestedPartyRole,
            { "NestedPartyRole (538)", "fix.NestedPartyRole",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NestedPartyRole", HFILL }
        },
        { &hf_fix_NoNestedPartyIDs,
            { "NoNestedPartyIDs (539)", "fix.NoNestedPartyIDs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoNestedPartyIDs", HFILL }
        },
        { &hf_fix_TotalAccruedInterestAmt,
            { "TotalAccruedInterestAmt (540)", "fix.TotalAccruedInterestAmt",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalAccruedInterestAmt", HFILL }
        },
        { &hf_fix_MaturityDate,
            { "MaturityDate (541)", "fix.MaturityDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MaturityDate", HFILL }
        },
        { &hf_fix_UnderlyingMaturityDate,
            { "UnderlyingMaturityDate (542)", "fix.UnderlyingMaturityDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingMaturityDate", HFILL }
        },
        { &hf_fix_InstrRegistry,
            { "InstrRegistry (543)", "fix.InstrRegistry",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "InstrRegistry", HFILL }
        },
        { &hf_fix_CashMargin,
            { "CashMargin (544)", "fix.CashMargin",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CashMargin", HFILL }
        },
        { &hf_fix_NestedPartySubID,
            { "NestedPartySubID (545)", "fix.NestedPartySubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NestedPartySubID", HFILL }
        },
        { &hf_fix_Scope,
            { "Scope (546)", "fix.Scope",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Scope", HFILL }
        },
        { &hf_fix_MDImplicitDelete,
            { "MDImplicitDelete (547)", "fix.MDImplicitDelete",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MDImplicitDelete", HFILL }
        },
        { &hf_fix_CrossID,
            { "CrossID (548)", "fix.CrossID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CrossID", HFILL }
        },
        { &hf_fix_CrossType,
            { "CrossType (549)", "fix.CrossType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CrossType", HFILL }
        },
        { &hf_fix_CrossPrioritization,
            { "CrossPrioritization (550)", "fix.CrossPrioritization",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CrossPrioritization", HFILL }
        },
        { &hf_fix_OrigCrossID,
            { "OrigCrossID (551)", "fix.OrigCrossID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrigCrossID", HFILL }
        },
        { &hf_fix_NoSides,
            { "NoSides (552)", "fix.NoSides",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoSides", HFILL }
        },
        { &hf_fix_Username,
            { "Username (553)", "fix.Username",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Username", HFILL }
        },
        { &hf_fix_Password,
            { "Password (554)", "fix.Password",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Password", HFILL }
        },
        { &hf_fix_NoLegs,
            { "NoLegs (555)", "fix.NoLegs",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoLegs", HFILL }
        },
        { &hf_fix_LegCurrency,
            { "LegCurrency (556)", "fix.LegCurrency",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCurrency", HFILL }
        },
        { &hf_fix_TotalNumSecurityTypes,
            { "TotalNumSecurityTypes (557)", "fix.TotalNumSecurityTypes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TotalNumSecurityTypes", HFILL }
        },
        { &hf_fix_NoSecurityTypes,
            { "NoSecurityTypes (558)", "fix.NoSecurityTypes",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoSecurityTypes", HFILL }
        },
        { &hf_fix_SecurityListRequestType,
            { "SecurityListRequestType (559)", "fix.SecurityListRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityListRequestType", HFILL }
        },
        { &hf_fix_SecurityRequestResult,
            { "SecurityRequestResult (560)", "fix.SecurityRequestResult",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecurityRequestResult", HFILL }
        },
        { &hf_fix_RoundLot,
            { "RoundLot (561)", "fix.RoundLot",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RoundLot", HFILL }
        },
        { &hf_fix_MinTradeVol,
            { "MinTradeVol (562)", "fix.MinTradeVol",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MinTradeVol", HFILL }
        },
        { &hf_fix_MultiLegRptTypeReq,
            { "MultiLegRptTypeReq (563)", "fix.MultiLegRptTypeReq",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MultiLegRptTypeReq", HFILL }
        },
        { &hf_fix_LegPositionEffect,
            { "LegPositionEffect (564)", "fix.LegPositionEffect",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegPositionEffect", HFILL }
        },
        { &hf_fix_LegCoveredOrUncovered,
            { "LegCoveredOrUncovered (565)", "fix.LegCoveredOrUncovered",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCoveredOrUncovered", HFILL }
        },
        { &hf_fix_LegPrice,
            { "LegPrice (566)", "fix.LegPrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegPrice", HFILL }
        },
        { &hf_fix_TradSesStatusRejReason,
            { "TradSesStatusRejReason (567)", "fix.TradSesStatusRejReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradSesStatusRejReason", HFILL }
        },
        { &hf_fix_TradeRequestID,
            { "TradeRequestID (568)", "fix.TradeRequestID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeRequestID", HFILL }
        },
        { &hf_fix_TradeRequestType,
            { "TradeRequestType (569)", "fix.TradeRequestType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeRequestType", HFILL }
        },
        { &hf_fix_PreviouslyReported,
            { "PreviouslyReported (570)", "fix.PreviouslyReported",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PreviouslyReported", HFILL }
        },
        { &hf_fix_TradeReportID,
            { "TradeReportID (571)", "fix.TradeReportID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeReportID", HFILL }
        },
        { &hf_fix_TradeReportRefID,
            { "TradeReportRefID (572)", "fix.TradeReportRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeReportRefID", HFILL }
        },
        { &hf_fix_MatchStatus,
            { "MatchStatus (573)", "fix.MatchStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MatchStatus", HFILL }
        },
        { &hf_fix_MatchType,
            { "MatchType (574)", "fix.MatchType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MatchType", HFILL }
        },
        { &hf_fix_OddLot,
            { "OddLot (575)", "fix.OddLot",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OddLot", HFILL }
        },
        { &hf_fix_NoClearingInstructions,
            { "NoClearingInstructions (576)", "fix.NoClearingInstructions",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoClearingInstructions", HFILL }
        },
        { &hf_fix_ClearingInstruction,
            { "ClearingInstruction (577)", "fix.ClearingInstruction",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClearingInstruction", HFILL }
        },
        { &hf_fix_TradeInputSource,
            { "TradeInputSource (578)", "fix.TradeInputSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeInputSource", HFILL }
        },
        { &hf_fix_TradeInputDevice,
            { "TradeInputDevice (579)", "fix.TradeInputDevice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradeInputDevice", HFILL }
        },
        { &hf_fix_NoDates,
            { "NoDates (580)", "fix.NoDates",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoDates", HFILL }
        },
        { &hf_fix_AccountType,
            { "AccountType (581)", "fix.AccountType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AccountType", HFILL }
        },
        { &hf_fix_CustOrderCapacity,
            { "CustOrderCapacity (582)", "fix.CustOrderCapacity",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "CustOrderCapacity", HFILL }
        },
        { &hf_fix_ClOrdLinkID,
            { "ClOrdLinkID (583)", "fix.ClOrdLinkID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClOrdLinkID", HFILL }
        },
        { &hf_fix_MassStatusReqID,
            { "MassStatusReqID (584)", "fix.MassStatusReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MassStatusReqID", HFILL }
        },
        { &hf_fix_MassStatusReqType,
            { "MassStatusReqType (585)", "fix.MassStatusReqType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MassStatusReqType", HFILL }
        },
        { &hf_fix_OrigOrdModTime,
            { "OrigOrdModTime (586)", "fix.OrigOrdModTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OrigOrdModTime", HFILL }
        },
        { &hf_fix_LegSettlmntTyp,
            { "LegSettlmntTyp (587)", "fix.LegSettlmntTyp",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSettlmntTyp", HFILL }
        },
        { &hf_fix_LegFutSettDate,
            { "LegFutSettDate (588)", "fix.LegFutSettDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegFutSettDate", HFILL }
        },
        { &hf_fix_DayBookingInst,
            { "DayBookingInst (589)", "fix.DayBookingInst",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "DayBookingInst", HFILL }
        },
        { &hf_fix_BookingUnit,
            { "BookingUnit (590)", "fix.BookingUnit",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BookingUnit", HFILL }
        },
        { &hf_fix_PreallocMethod,
            { "PreallocMethod (591)", "fix.PreallocMethod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PreallocMethod", HFILL }
        },
        { &hf_fix_UnderlyingCountryOfIssue,
            { "UnderlyingCountryOfIssue (592)", "fix.UnderlyingCountryOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingCountryOfIssue", HFILL }
        },
        { &hf_fix_UnderlyingStateOrProvinceOfIssue,
            { "UnderlyingStateOrProvinceOfIssue (593)", "fix.UnderlyingStateOrProvinceOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingStateOrProvinceOfIssue", HFILL }
        },
        { &hf_fix_UnderlyingLocaleOfIssue,
            { "UnderlyingLocaleOfIssue (594)", "fix.UnderlyingLocaleOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingLocaleOfIssue", HFILL }
        },
        { &hf_fix_UnderlyingInstrRegistry,
            { "UnderlyingInstrRegistry (595)", "fix.UnderlyingInstrRegistry",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingInstrRegistry", HFILL }
        },
        { &hf_fix_LegCountryOfIssue,
            { "LegCountryOfIssue (596)", "fix.LegCountryOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCountryOfIssue", HFILL }
        },
        { &hf_fix_LegStateOrProvinceOfIssue,
            { "LegStateOrProvinceOfIssue (597)", "fix.LegStateOrProvinceOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegStateOrProvinceOfIssue", HFILL }
        },
        { &hf_fix_LegLocaleOfIssue,
            { "LegLocaleOfIssue (598)", "fix.LegLocaleOfIssue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegLocaleOfIssue", HFILL }
        },
        { &hf_fix_LegInstrRegistry,
            { "LegInstrRegistry (599)", "fix.LegInstrRegistry",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegInstrRegistry", HFILL }
        },
        { &hf_fix_LegSymbol,
            { "LegSymbol (600)", "fix.LegSymbol",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSymbol", HFILL }
        },
        { &hf_fix_LegSymbolSfx,
            { "LegSymbolSfx (601)", "fix.LegSymbolSfx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSymbolSfx", HFILL }
        },
        { &hf_fix_LegSecurityID,
            { "LegSecurityID (602)", "fix.LegSecurityID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityID", HFILL }
        },
        { &hf_fix_LegSecurityIDSource,
            { "LegSecurityIDSource (603)", "fix.LegSecurityIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityIDSource", HFILL }
        },
        { &hf_fix_NoLegSecurityAltID,
            { "NoLegSecurityAltID (604)", "fix.NoLegSecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoLegSecurityAltID", HFILL }
        },
        { &hf_fix_LegSecurityAltID,
            { "LegSecurityAltID (605)", "fix.LegSecurityAltID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityAltID", HFILL }
        },
        { &hf_fix_LegSecurityAltIDSource,
            { "LegSecurityAltIDSource (606)", "fix.LegSecurityAltIDSource",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityAltIDSource", HFILL }
        },
        { &hf_fix_LegProduct,
            { "LegProduct (607)", "fix.LegProduct",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegProduct", HFILL }
        },
        { &hf_fix_LegCFICode,
            { "LegCFICode (608)", "fix.LegCFICode",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCFICode", HFILL }
        },
        { &hf_fix_LegSecurityType,
            { "LegSecurityType (609)", "fix.LegSecurityType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityType", HFILL }
        },
        { &hf_fix_LegMaturityMonthYear,
            { "LegMaturityMonthYear (610)", "fix.LegMaturityMonthYear",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegMaturityMonthYear", HFILL }
        },
        { &hf_fix_LegMaturityDate,
            { "LegMaturityDate (611)", "fix.LegMaturityDate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegMaturityDate", HFILL }
        },
        { &hf_fix_LegStrikePrice,
            { "LegStrikePrice (612)", "fix.LegStrikePrice",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegStrikePrice", HFILL }
        },
        { &hf_fix_LegOptAttribute,
            { "LegOptAttribute (613)", "fix.LegOptAttribute",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegOptAttribute", HFILL }
        },
        { &hf_fix_LegContractMultiplier,
            { "LegContractMultiplier (614)", "fix.LegContractMultiplier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegContractMultiplier", HFILL }
        },
        { &hf_fix_LegCouponRate,
            { "LegCouponRate (615)", "fix.LegCouponRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegCouponRate", HFILL }
        },
        { &hf_fix_LegSecurityExchange,
            { "LegSecurityExchange (616)", "fix.LegSecurityExchange",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityExchange", HFILL }
        },
        { &hf_fix_LegIssuer,
            { "LegIssuer (617)", "fix.LegIssuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegIssuer", HFILL }
        },
        { &hf_fix_EncodedLegIssuerLen,
            { "EncodedLegIssuerLen (618)", "fix.EncodedLegIssuerLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedLegIssuerLen", HFILL }
        },
        { &hf_fix_EncodedLegIssuer,
            { "EncodedLegIssuer (619)", "fix.EncodedLegIssuer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedLegIssuer", HFILL }
        },
        { &hf_fix_LegSecurityDesc,
            { "LegSecurityDesc (620)", "fix.LegSecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSecurityDesc", HFILL }
        },
        { &hf_fix_EncodedLegSecurityDescLen,
            { "EncodedLegSecurityDescLen (621)", "fix.EncodedLegSecurityDescLen",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedLegSecurityDescLen", HFILL }
        },
        { &hf_fix_EncodedLegSecurityDesc,
            { "EncodedLegSecurityDesc (622)", "fix.EncodedLegSecurityDesc",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "EncodedLegSecurityDesc", HFILL }
        },
        { &hf_fix_LegRatioQty,
            { "LegRatioQty (623)", "fix.LegRatioQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRatioQty", HFILL }
        },
        { &hf_fix_LegSide,
            { "LegSide (624)", "fix.LegSide",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegSide", HFILL }
        },
        { &hf_fix_TradingSessionSubID,
            { "TradingSessionSubID (625)", "fix.TradingSessionSubID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "TradingSessionSubID", HFILL }
        },
        { &hf_fix_AllocType,
            { "AllocType (626)", "fix.AllocType",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "AllocType", HFILL }
        },
        { &hf_fix_NoHops,
            { "NoHops (627)", "fix.NoHops",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "NoHops", HFILL }
        },
        { &hf_fix_HopCompID,
            { "HopCompID (628)", "fix.HopCompID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HopCompID", HFILL }
        },
        { &hf_fix_HopSendingTime,
            { "HopSendingTime (629)", "fix.HopSendingTime",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HopSendingTime", HFILL }
        },
        { &hf_fix_HopRefID,
            { "HopRefID (630)", "fix.HopRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "HopRefID", HFILL }
        },
        { &hf_fix_MidPx,
            { "MidPx (631)", "fix.MidPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MidPx", HFILL }
        },
        { &hf_fix_BidYield,
            { "BidYield (632)", "fix.BidYield",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidYield", HFILL }
        },
        { &hf_fix_MidYield,
            { "MidYield (633)", "fix.MidYield",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MidYield", HFILL }
        },
        { &hf_fix_OfferYield,
            { "OfferYield (634)", "fix.OfferYield",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferYield", HFILL }
        },
        { &hf_fix_ClearingFeeIndicator,
            { "ClearingFeeIndicator (635)", "fix.ClearingFeeIndicator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ClearingFeeIndicator", HFILL }
        },
        { &hf_fix_WorkingIndicator,
            { "WorkingIndicator (636)", "fix.WorkingIndicator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WorkingIndicator", HFILL }
        },
        { &hf_fix_LegLastPx,
            { "LegLastPx (637)", "fix.LegLastPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegLastPx", HFILL }
        },
        { &hf_fix_PriorityIndicator,
            { "PriorityIndicator (638)", "fix.PriorityIndicator",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PriorityIndicator", HFILL }
        },
        { &hf_fix_PriceImprovement,
            { "PriceImprovement (639)", "fix.PriceImprovement",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "PriceImprovement", HFILL }
        },
        { &hf_fix_Price2,
            { "Price2 (640)", "fix.Price2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Price2", HFILL }
        },
        { &hf_fix_LastForwardPoints2,
            { "LastForwardPoints2 (641)", "fix.LastForwardPoints2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LastForwardPoints2", HFILL }
        },
        { &hf_fix_BidForwardPoints2,
            { "BidForwardPoints2 (642)", "fix.BidForwardPoints2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "BidForwardPoints2", HFILL }
        },
        { &hf_fix_OfferForwardPoints2,
            { "OfferForwardPoints2 (643)", "fix.OfferForwardPoints2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "OfferForwardPoints2", HFILL }
        },
        { &hf_fix_RFQReqID,
            { "RFQReqID (644)", "fix.RFQReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "RFQReqID", HFILL }
        },
        { &hf_fix_MktBidPx,
            { "MktBidPx (645)", "fix.MktBidPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MktBidPx", HFILL }
        },
        { &hf_fix_MktOfferPx,
            { "MktOfferPx (646)", "fix.MktOfferPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MktOfferPx", HFILL }
        },
        { &hf_fix_MinBidSize,
            { "MinBidSize (647)", "fix.MinBidSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MinBidSize", HFILL }
        },
        { &hf_fix_MinOfferSize,
            { "MinOfferSize (648)", "fix.MinOfferSize",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "MinOfferSize", HFILL }
        },
        { &hf_fix_QuoteStatusReqID,
            { "QuoteStatusReqID (649)", "fix.QuoteStatusReqID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteStatusReqID", HFILL }
        },
        { &hf_fix_LegalConfirm,
            { "LegalConfirm (650)", "fix.LegalConfirm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegalConfirm", HFILL }
        },
        { &hf_fix_UnderlyingLastPx,
            { "UnderlyingLastPx (651)", "fix.UnderlyingLastPx",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingLastPx", HFILL }
        },
        { &hf_fix_UnderlyingLastQty,
            { "UnderlyingLastQty (652)", "fix.UnderlyingLastQty",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UnderlyingLastQty", HFILL }
        },
        { &hf_fix_SecDefStatus,
            { "SecDefStatus (653)", "fix.SecDefStatus",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SecDefStatus", HFILL }
        },
        { &hf_fix_LegRefID,
            { "LegRefID (654)", "fix.LegRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "LegRefID", HFILL }
        },
        { &hf_fix_ContraLegRefID,
            { "ContraLegRefID (655)", "fix.ContraLegRefID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "ContraLegRefID", HFILL }
        },
        { &hf_fix_SettlCurrBidFxRate,
            { "SettlCurrBidFxRate (656)", "fix.SettlCurrBidFxRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrBidFxRate", HFILL }
        },
        { &hf_fix_SettlCurrOfferFxRate,
            { "SettlCurrOfferFxRate (657)", "fix.SettlCurrOfferFxRate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SettlCurrOfferFxRate", HFILL }
        },
        { &hf_fix_QuoteRequestRejectReason,
            { "QuoteRequestRejectReason (658)", "fix.QuoteRequestRejectReason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "QuoteRequestRejectReason", HFILL }
        },
        { &hf_fix_SideComplianceID,
            { "SideComplianceID (659)", "fix.SideComplianceID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "SideComplianceID", HFILL }
        },
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fix,
    };

    /* register re-init routine */
    register_init_routine(&dissect_fix_init);

    /* Register the protocol name and description */
    proto_fix = proto_register_protocol("Financial Information eXchange Protocol",
        "FIX", "fix");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fix, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fix(void)
{
    /*
     * The first time the function is called let the tcp dissector
     * know that we're interested in traffic
     */
    heur_dissector_add("tcp", dissect_fix, proto_fix);
}

