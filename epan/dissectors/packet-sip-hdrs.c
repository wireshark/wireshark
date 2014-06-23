/* ANSI-C code produced by gperf version 3.0.4 */
/* Command-line: gperf -m 500 -D packet-sip-hdrs.gperf  */
/* Computed positions: -k'1,3,7,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 1 "packet-sip-hdrs.gperf"

#include <string.h>

#include "packet-sip-hdrs.h"
#line 16 "packet-sip-hdrs.gperf"
struct name_pos { const char *name; int pos; };

#define TOTAL_KEYWORDS 134
#define MIN_WORD_LENGTH 1
#define MAX_WORD_LENGTH 29
#define MIN_HASH_VALUE 3
#define MAX_HASH_VALUE 220
/* maximum key range = 218, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
_sip_header_hash (register const char *str, register unsigned int len)
{
  static const unsigned char asso_values[] =
    {
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221,  55, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221,  27,  11,   4,
       54,   2,  75,  32, 103,  21,   6,  35,  12,  86,
        3,  39,   6,  34,   9,   7,   1,  82,  58,  86,
        8,  59,   4, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
      221, 221, 221, 221, 221, 221
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
      case 5:
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#if defined __GNUC_STDC_INLINE__ || defined __GNUC_GNU_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct name_pos *
_sip_header_find (register const char *str, register unsigned int len)
{
  static const unsigned char lengthtable[] =
    {
       1,  1,  1,  1,  5,  1,  1,  7,  1,  1, 12,  1,  1, 16,
       7, 15,  7, 19,  6,  8, 13,  4, 19, 15, 13,  6, 15, 18,
       2,  1,  4,  6, 15, 16,  4, 14,  4,  7,  1, 16, 11, 18,
      12,  4, 18,  8,  9, 13, 19,  9, 17, 13,  1, 18, 16, 13,
       9, 29,  1,  8, 10, 12, 17, 14, 14, 15, 19, 14, 10, 12,
       8, 18, 20, 19,  8, 17,  6,  5, 10, 21, 14, 11, 15, 13,
      13, 13,  1, 13,  9, 11, 11,  4,  3, 10,  1,  1, 19, 12,
      12, 17, 14, 10, 18,  9,  5,  7,  8, 15, 20,  9, 12, 11,
      20, 17, 21, 12,  9, 19,  1,  7, 10, 11, 15,  1,  7, 24,
       1, 12, 12, 16, 11,  4, 11, 12
    };
  static const struct name_pos wordlist[] =
    {
#line 151 "packet-sip-hdrs.gperf"
      {"t", POS_TO},
#line 137 "packet-sip-hdrs.gperf"
      {"e", POS_CONTENT_ENCODING},
#line 143 "packet-sip-hdrs.gperf"
      {"n", POS_IDENTITY_INFO},
#line 139 "packet-sip-hdrs.gperf"
      {"c", POS_CONTENT_TYPE},
#line 41 "packet-sip-hdrs.gperf"
      {"event", POS_EVENT},
#line 146 "packet-sip-hdrs.gperf"
      {"j", POS_REJECT_CONTACT},
#line 149 "packet-sip-hdrs.gperf"
      {"s", POS_SUBJECT},
#line 32 "packet-sip-hdrs.gperf"
      {"contact", POS_CONTACT},
#line 148 "packet-sip-hdrs.gperf"
      {"x", POS_SESSION_EXPIRES},
#line 144 "packet-sip-hdrs.gperf"
      {"r", POS_REFER_TO},
#line 37 "packet-sip-hdrs.gperf"
      {"content-type", POS_CONTENT_TYPE},
#line 145 "packet-sip-hdrs.gperf"
      {"b", POS_REFERED_BY},
#line 138 "packet-sip-hdrs.gperf"
      {"l", POS_CONTENT_LENGTH},
#line 35 "packet-sip-hdrs.gperf"
      {"content-language", POS_CONTENT_LANGUAGE},
#line 118 "packet-sip-hdrs.gperf"
      {"subject", POS_SUBJECT},
#line 110 "packet-sip-hdrs.gperf"
      {"security-client", POS_SECURITY_CLIENT},
#line 42 "packet-sip-hdrs.gperf"
      {"expires", POS_EXPIRES},
#line 33 "packet-sip-hdrs.gperf"
      {"content-disposition", POS_CONTENT_DISPOSITION},
#line 113 "packet-sip-hdrs.gperf"
      {"server", POS_SERVER},
#line 102 "packet-sip-hdrs.gperf"
      {"replaces", POS_REPLACES},
#line 114 "packet-sip-hdrs.gperf"
      {"service-route", POS_SERVICE_ROUTE},
#line 54 "packet-sip-hdrs.gperf"
      {"join", POS_JOIN},
#line 77 "packet-sip-hdrs.gperf"
      {"p-preferred-service", POS_P_PREFERRED_SERV},
#line 111 "packet-sip-hdrs.gperf"
      {"security-server", POS_SECURITY_SERVER},
#line 80 "packet-sip-hdrs.gperf"
      {"p-served-user", POS_P_SERVED_USER},
#line 19 "packet-sip-hdrs.gperf"
      {"accept",	POS_ACCEPT},
#line 115 "packet-sip-hdrs.gperf"
      {"session-expires", POS_SESSION_EXPIRES},
#line 79 "packet-sip-hdrs.gperf"
      {"p-refused-uri-list", POS_P_REFUSED_URI_LST},
#line 124 "packet-sip-hdrs.gperf"
      {"to", POS_TO},
#line 135 "packet-sip-hdrs.gperf"
      {"i", POS_CALL_ID},
#line 38 "packet-sip-hdrs.gperf"
      {"cseq", POS_CSEQ},
#line 94 "packet-sip-hdrs.gperf"
      {"reason", POS_REASON},
#line 125 "packet-sip-hdrs.gperf"
      {"trigger-consent", POS_TRIGGER_CONSENT},
#line 88 "packet-sip-hdrs.gperf"
      {"priv-answer-mode", POS_PRIV_ANSWER_MODE},
#line 109 "packet-sip-hdrs.gperf"
      {"rseq", POS_RSEQ},
#line 62 "packet-sip-hdrs.gperf"
      {"p-answer-state", POS_P_ANSWER_STATE},
#line 93 "packet-sip-hdrs.gperf"
      {"rack", POS_RACK},
#line 105 "packet-sip-hdrs.gperf"
      {"require", POS_REQUIRE},
#line 133 "packet-sip-hdrs.gperf"
      {"a", POS_ACCEPT_CONTACT},
#line 34 "packet-sip-hdrs.gperf"
      {"content-encoding", POS_CONTENT_ENCODING},
#line 107 "packet-sip-hdrs.gperf"
      {"retry-after", POS_RETRY_AFTER},
#line 119 "packet-sip-hdrs.gperf"
      {"subscription-state", POS_SUBSCRIPTION_STATE},
#line 26 "packet-sip-hdrs.gperf"
      {"allow-events", POS_ALLOW_EVENTS},
#line 39 "packet-sip-hdrs.gperf"
      {"date", POS_DATE},
#line 64 "packet-sip-hdrs.gperf"
      {"p-asserted-service", POS_P_ASSERTED_SERV},
#line 103 "packet-sip-hdrs.gperf"
      {"reply-to", POS_REPLY_TO},
#line 97 "packet-sip-hdrs.gperf"
      {"recv-info", POS_RECV_INFO},
#line 29 "packet-sip-hdrs.gperf"
      {"authorization", POS_AUTHORIZATION},
#line 104 "packet-sip-hdrs.gperf"
      {"request-disposition", POS_REQUEST_DISPOSITION},
#line 31 "packet-sip-hdrs.gperf"
      {"call-info", POS_CALL_INFO},
#line 68 "packet-sip-hdrs.gperf"
      {"p-charging-vector", POS_P_CHARGING_VECTOR},
#line 92 "packet-sip-hdrs.gperf"
      {"proxy-require", POS_PROXY_REQUIRE},
#line 150 "packet-sip-hdrs.gperf"
      {"k", POS_SUPPORTED},
#line 84 "packet-sip-hdrs.gperf"
      {"permission-missing", POS_PERMISSION_MISSING},
#line 65 "packet-sip-hdrs.gperf"
      {"p-associated-uri", POS_P_ASSOCIATED_URI},
#line 51 "packet-sip-hdrs.gperf"
      {"identity-info", POS_IDENTITY_INFO},
#line 120 "packet-sip-hdrs.gperf"
      {"supported", POS_SUPPORTED},
#line 67 "packet-sip-hdrs.gperf"
      {"p-charging-function-addresses", POS_P_CHARGING_FUNC_ADDRESSES},
#line 140 "packet-sip-hdrs.gperf"
      {"o", POS_EVENT},
#line 116 "packet-sip-hdrs.gperf"
      {"sip-etag", POS_SIP_ETAG},
#line 40 "packet-sip-hdrs.gperf"
      {"error-info", POS_ERROR_INFO},
#line 96 "packet-sip-hdrs.gperf"
      {"record-route", POS_RECORD_ROUTE},
#line 66 "packet-sip-hdrs.gperf"
      {"p-called-party-id", POS_P_CALLED_PARTY_ID},
#line 73 "packet-sip-hdrs.gperf"
      {"p-dcs-redirect", POS_P_DCS_REDIRECT},
#line 101 "packet-sip-hdrs.gperf"
      {"reject-contact", POS_REJECT_CONTACT},
#line 112 "packet-sip-hdrs.gperf"
      {"security-verify", POS_SECURITY_VERIFY},
#line 28 "packet-sip-hdrs.gperf"
      {"authentication-info", POS_AUTHENTICATION_INFO},
#line 85 "packet-sip-hdrs.gperf"
      {"policy-contact", POS_POLICY_CONTACT},
#line 72 "packet-sip-hdrs.gperf"
      {"p-dcs-laes", POS_P_DCS_LAES},
#line 60 "packet-sip-hdrs.gperf"
      {"organization", POS_ORGANIZATION},
#line 50 "packet-sip-hdrs.gperf"
      {"identity", POS_IDENTITY},
#line 90 "packet-sip-hdrs.gperf"
      {"proxy-authenticate", POS_PROXY_AUTHENTICATE},
#line 76 "packet-sip-hdrs.gperf"
      {"p-preferred-identity", POS_P_PREFERRED_IDENTITY},
#line 91 "packet-sip-hdrs.gperf"
      {"proxy-authorization", POS_PROXY_AUTHORIZATION},
#line 87 "packet-sip-hdrs.gperf"
      {"priority", POS_PRIORITY},
#line 106 "packet-sip-hdrs.gperf"
      {"resource-priority", POS_RESOURCE_PRIORITY},
#line 59 "packet-sip-hdrs.gperf"
      {"min-se", POS_MIN_SE},
#line 108 "packet-sip-hdrs.gperf"
      {"route", POS_ROUTE},
#line 24 "packet-sip-hdrs.gperf"
      {"alert-info", POS_ALERT_INFO},
#line 61 "packet-sip-hdrs.gperf"
      {"p-access-network-info", POS_P_ACCESS_NETWORK_INFO},
#line 20 "packet-sip-hdrs.gperf"
      {"accept-contact", POS_ACCEPT_CONTACT},
#line 27 "packet-sip-hdrs.gperf"
      {"answer-mode", POS_ANSWER_MODE},
#line 22 "packet-sip-hdrs.gperf"
      {"accept-language", POS_ACCEPT_LANGUAGE},
#line 78 "packet-sip-hdrs.gperf"
      {"p-profile-key", POS_P_PROFILE_KEY},
#line 95 "packet-sip-hdrs.gperf"
      {"reason-phrase", POS_REASON_PHRASE},
#line 74 "packet-sip-hdrs.gperf"
      {"p-early-media", POS_P_EARLY_MEDIA},
#line 147 "packet-sip-hdrs.gperf"
      {"d", POS_REQUEST_DISPOSITION},
#line 122 "packet-sip-hdrs.gperf"
      {"target-dialog", POS_TARGET_DIALOG},
#line 98 "packet-sip-hdrs.gperf"
      {"refer-sub", POS_REFER_SUB},
#line 46 "packet-sip-hdrs.gperf"
      {"geolocation", POS_GEOLOCATION},
#line 58 "packet-sip-hdrs.gperf"
      {"min-expires", POS_MIN_EXPIRES},
#line 83 "packet-sip-hdrs.gperf"
      {"path", POS_PATH},
#line 128 "packet-sip-hdrs.gperf"
      {"via", POS_VIA},
#line 70 "packet-sip-hdrs.gperf"
      {"p-dcs-osps", POS_P_DCS_OSPS},
#line 152 "packet-sip-hdrs.gperf"
      {"v", POS_VIA},
#line 142 "packet-sip-hdrs.gperf"
      {"y", POS_IDENTITY},
#line 63 "packet-sip-hdrs.gperf"
      {"p-asserted-identity", POS_P_ASSERTED_IDENTITY},
#line 56 "packet-sip-hdrs.gperf"
      {"max-forwards", POS_MAX_FORWARDS},
#line 43 "packet-sip-hdrs.gperf"
      {"feature-caps", POS_FEATURE_CAPS},
#line 47 "packet-sip-hdrs.gperf"
      {"geolocation-error", POS_GEOLOCATION_ERROR},
#line 36 "packet-sip-hdrs.gperf"
      {"content-length", POS_CONTENT_LENGTH},
#line 127 "packet-sip-hdrs.gperf"
      {"user-agent", POS_USER_AGENT},
#line 71 "packet-sip-hdrs.gperf"
      {"p-dcs-billing-info", POS_P_DCS_BILLING_INFO},
#line 123 "packet-sip-hdrs.gperf"
      {"timestamp", POS_TIMESTAMP},
#line 25 "packet-sip-hdrs.gperf"
      {"allow", POS_ALLOW},
#line 30 "packet-sip-hdrs.gperf"
      {"call-id", POS_CALL_ID},
#line 99 "packet-sip-hdrs.gperf"
      {"refer-to", POS_REFER_TO},
#line 21 "packet-sip-hdrs.gperf"
      {"accept-encoding", POS_ACCEPT_ENCODING},
#line 69 "packet-sip-hdrs.gperf"
      {"p-dcs-trace-party-id", POS_P_DCS_TRACE_PARTY_ID},
#line 86 "packet-sip-hdrs.gperf"
      {"policy-id", POS_POLICY_ID},
#line 52 "packet-sip-hdrs.gperf"
      {"info-package", POS_INFO_PKG},
#line 53 "packet-sip-hdrs.gperf"
      {"in-reply-to", POS_IN_REPLY_TO},
#line 82 "packet-sip-hdrs.gperf"
      {"p-visited-network-id", POS_P_VISITED_NETWORK_ID},
#line 121 "packet-sip-hdrs.gperf"
      {"suppress-if-match", POS_SUPPRESS_IF_MATCH},
#line 75 "packet-sip-hdrs.gperf"
      {"p-media-authorization", POS_P_MEDIA_AUTHORIZATION},
#line 132 "packet-sip-hdrs.gperf"
      {"user-to-user", POS_USER_TO_USER},
#line 131 "packet-sip-hdrs.gperf"
      {"diversion", POS_DIVERSION},
#line 48 "packet-sip-hdrs.gperf"
      {"geolocation-routing", POS_GEOLOCATION_ROUTING},
#line 141 "packet-sip-hdrs.gperf"
      {"f", POS_FROM},
#line 89 "packet-sip-hdrs.gperf"
      {"privacy", POS_PRIVACY},
#line 44 "packet-sip-hdrs.gperf"
      {"flow-timer", POS_FLOW_TIMER},
#line 100 "packet-sip-hdrs.gperf"
      {"referred-by", POS_REFERED_BY},
#line 81 "packet-sip-hdrs.gperf"
      {"p-user-database", POS_P_USER_DATABASE},
#line 134 "packet-sip-hdrs.gperf"
      {"u", POS_ALLOW_EVENTS},
#line 129 "packet-sip-hdrs.gperf"
      {"warning", POS_WARNING},
#line 23 "packet-sip-hdrs.gperf"
      {"accept-resource-priority", POS_ACCEPT_RESOURCE_PRIORITY},
#line 136 "packet-sip-hdrs.gperf"
      {"m", POS_CONTACT},
#line 117 "packet-sip-hdrs.gperf"
      {"sip-if-match", POS_SIP_IF_MATCH},
#line 57 "packet-sip-hdrs.gperf"
      {"mime-version", POS_MIME_VERSION},
#line 130 "packet-sip-hdrs.gperf"
      {"www-authenticate", POS_WWW_AUTHENTICATE},
#line 126 "packet-sip-hdrs.gperf"
      {"unsupported", POS_UNSUPPORTED},
#line 45 "packet-sip-hdrs.gperf"
      {"from", POS_FROM},
#line 55 "packet-sip-hdrs.gperf"
      {"max-breadth", POS_MAX_BREADTH},
#line 49 "packet-sip-hdrs.gperf"
      {"history-info", POS_HISTORY_INFO}
    };

  static const short lookup[] =
    {
       -1,  -1,  -1,   0,  -1,   1,  -1,   2,  -1,   3,
        4,  -1,  -1,   5,  -1,   6,   7,   8,  -1,   9,
       -1,  -1,  10,  11,  -1,  12,  13,  14,  15,  16,
       17,  18,  19,  20,  21,  22,  23,  24,  25,  26,
       -1,  27,  28,  29,  30,  31,  -1,  32,  33,  34,
       -1,  35,  36,  -1,  37,  38,  39,  40,  -1,  41,
       42,  43,  44,  45,  46,  47,  48,  49,  50,  51,
       -1,  52,  53,  -1,  54,  -1,  55,  56,  57,  58,
       59,  60,  61,  62,  63,  64,  65,  66,  67,  68,
       69,  70,  71,  72,  73,  74,  75,  76,  77,  78,
       79,  80,  81,  82,  -1,  83,  84,  85,  -1,  86,
       87,  88,  89,  90,  91,  92,  93,  94,  -1,  95,
       96,  -1,  97,  98,  99, 100,  -1, 101, 102, 103,
      104, 105, 106, 107,  -1, 108, 109, 110, 111, 112,
      113,  -1,  -1, 114, 115, 116,  -1,  -1,  -1, 117,
       -1, 118, 119,  -1, 120,  -1, 121,  -1,  -1,  -1,
      122,  -1,  -1,  -1,  -1, 123, 124,  -1,  -1, 125,
       -1,  -1,  -1, 126,  -1,  -1,  -1,  -1,  -1,  -1,
       -1,  -1,  -1, 127,  -1,  -1,  -1,  -1,  -1, 128,
       -1, 129,  -1, 130,  -1,  -1,  -1,  -1,  -1,  -1,
       -1,  -1,  -1,  -1, 131,  -1,  -1,  -1,  -1,  -1,
      132,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
      133
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = _sip_header_hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              if (len == lengthtable[index])
                {
                  register const char *s = wordlist[index].name;

                  if (*str == *s && !memcmp (str + 1, s + 1, len - 1))
                    return &wordlist[index];
                }
            }
        }
    }
  return 0;
}
#line 153 "packet-sip-hdrs.gperf"

int sip_is_known_sip_header(const char *header_name, unsigned int header_len)
{
	const struct name_pos *npos = _sip_header_find(header_name, header_len);

	if (!npos)
		return -1;
	return npos->pos;
}
