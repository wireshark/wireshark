/* asn1.c
 * Common routines for ASN.1
 * 2007  Anders Broman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <fenv.h>

#include <epan/packet.h>
#include <wsutil/pint.h>
#include <wsutil/sign_ext.h>

#include "asn1.h"

void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, bool aligned, packet_info *pinfo) {
  memset(actx, '\0', sizeof(*actx));
  actx->signature = ASN1_CTX_SIGNATURE;
  actx->encoding = encoding;
  actx->aligned = aligned;
  actx->pinfo = pinfo;
}

bool asn1_ctx_check_signature(asn1_ctx_t *actx) {
  return actx && (actx->signature == ASN1_CTX_SIGNATURE);
}

void asn1_ctx_clean_external(asn1_ctx_t *actx) {
  memset(&actx->external, '\0', sizeof(actx->external));
  actx->external.hf_index = -1;
  actx->external.encoding = -1;
}

void asn1_ctx_clean_epdv(asn1_ctx_t *actx) {
  memset(&actx->embedded_pdv, '\0', sizeof(actx->embedded_pdv));
  actx->embedded_pdv.hf_index = -1;
  actx->embedded_pdv.identification = -1;
}


/*--- stack/parameters ---*/

void asn1_stack_frame_push(asn1_ctx_t *actx, const char *name) {
  asn1_stack_frame_t *frame;

  frame = wmem_new0(actx->pinfo->pool, asn1_stack_frame_t);
  frame->name = name;
  frame->next = actx->stack;
  actx->stack = frame;
}

void asn1_stack_frame_pop(asn1_ctx_t *actx, const char *name) {
  DISSECTOR_ASSERT(actx->stack);
  DISSECTOR_ASSERT(!strcmp(actx->stack->name, name));
  actx->stack = actx->stack->next;
}

void asn1_stack_frame_check(asn1_ctx_t *actx, const char *name, const asn1_par_def_t *par_def) {
  const asn1_par_def_t *pd = par_def;
  asn1_par_t *par;

  DISSECTOR_ASSERT(actx->stack);
  DISSECTOR_ASSERT(!strcmp(actx->stack->name, name));

  par = actx->stack->par;
  while (pd->name) {
    DISSECTOR_ASSERT(par);
    DISSECTOR_ASSERT((pd->ptype == ASN1_PAR_IRR) || (par->ptype == pd->ptype));
    par->name = pd->name;
    pd++;
    par = par->next;
  }
  DISSECTOR_ASSERT(!par);
}

static asn1_par_t *get_par_by_name(asn1_ctx_t *actx, const char *name) {
  asn1_par_t *par = NULL;

  DISSECTOR_ASSERT(actx->stack);
  par = actx->stack->par;
  while (par) {
    if (!strcmp(par->name, name))
      return par;
    par = par->next;
  }
  return par;
}

static asn1_par_t *push_new_par(asn1_ctx_t *actx) {
  asn1_par_t *par, **pp;

  DISSECTOR_ASSERT(actx->stack);

  par = wmem_new0(actx->pinfo->pool, asn1_par_t);

  pp = &(actx->stack->par);
  while (*pp)
    pp = &((*pp)->next);
  *pp = par;

  return par;
}

void asn1_param_push_boolean(asn1_ctx_t *actx, bool value) {
  asn1_par_t *par;

  par = push_new_par(actx);
  par->ptype = ASN1_PAR_BOOLEAN;
  par->value.v_boolean = value;
}

void asn1_param_push_integer(asn1_ctx_t *actx, int32_t value) {
  asn1_par_t *par;

  par = push_new_par(actx);
  par->ptype = ASN1_PAR_INTEGER;
  par->value.v_integer = value;
}

bool asn1_param_get_boolean(asn1_ctx_t *actx, const char *name) {
  asn1_par_t *par = NULL;

  par = get_par_by_name(actx, name);
  DISSECTOR_ASSERT(par);
  return par->value.v_boolean;
}

int32_t asn1_param_get_integer(asn1_ctx_t *actx, const char *name) {
  asn1_par_t *par = NULL;

  par = get_par_by_name(actx, name);
  DISSECTOR_ASSERT(par);
  return par->value.v_integer;
}


/*--- ROSE ---*/

void rose_ctx_init(rose_ctx_t *rctx) {
  memset(rctx, '\0', sizeof(*rctx));
  rctx->signature = ROSE_CTX_SIGNATURE;
}

bool rose_ctx_check_signature(rose_ctx_t *rctx) {
  return rctx && (rctx->signature == ROSE_CTX_SIGNATURE);
}

void rose_ctx_clean_data(rose_ctx_t *rctx) {
  memset(&rctx->d, '\0', sizeof(rctx->d));
  rctx->d.code = -1;
}

asn1_ctx_t *get_asn1_ctx(void *ptr) {
  asn1_ctx_t *actx = (asn1_ctx_t*)ptr;

  if (!asn1_ctx_check_signature(actx))
    actx = NULL;

  return actx;
}

rose_ctx_t *get_rose_ctx(void *ptr) {
  rose_ctx_t *rctx = (rose_ctx_t*)ptr;
  asn1_ctx_t *actx = (asn1_ctx_t*)ptr;

  if (!asn1_ctx_check_signature(actx))
    actx = NULL;

  if (actx)
    rctx = actx->rose_ctx;

  if (!rose_ctx_check_signature(rctx))
    rctx = NULL;

  return rctx;
}

static double
asn1_get_overflow(uint8_t first_octet, int S) {
  if (first_octet & 0x80) {
    // Negative exponent
    return S * 0.0;
  } else {
    // Positive exponent
    return S * HUGE_VAL;
  }
}

#ifdef _MSC_VER
/* MSVC way of turning on floating point exceptions. */
#pragma float_control(precise, on, push)
#pragma float_control(except, on)
#pragma fenv_access(on)
#endif

double asn1_get_real(const uint8_t *real_ptr, int len, int *err) {
  uint8_t octet;
  const uint8_t *p;
  double val = 0;
  *err = 0;

  /* XXX - We don't check the asn1 context, and so allow any encoding which
   * is acceptable in BER, instead of setting EINVAL for overlong encodings
   * which are not allowed in CER and DER (11.3) nor PER, which uses the
   * same encoding as CER & DER for the real type after octet alignement
   * (X.691 15.2). Many of those will set ERANGE instead of EINVAL.
   */

  /* 8.5.2    If the real value is the value zero,
   *          there shall be no contents octets in the encoding.
   */
  if (len < 1) return val;

  octet = real_ptr[0];
  p = real_ptr + 1;
  len -= 1;
  if (octet & 0x80) {  /* binary encoding */
    int i;
    int8_t S; /* Sign */
    uint8_t B; /* log base 2 of the Base */
    uint8_t F; /* scaling Factor */
    int32_t E = 0; /* Exponent (supported max 3 octets/24 bit) */
    uint64_t N = 0; /* N (supported max 8 octets/64 bit) */
    int exp = 0;

    uint8_t lenE, lenN;

    if(octet & 0x40) S = -1; else S = 1;
    switch(octet & 0x30) {
      case 0x00: B = 1; break;
      case 0x10: B = 3; break;
      case 0x20: B = 4; break;
      case 0x30: /* Reserved */
      default:
        *err = EINVAL;
        return val;
    }
    F = (octet & 0x0c) >> 2;

    /* 8.5.7.4 Exponent length */
    lenE = (octet & 0x3) + 1;

    /* 8.5.7.4 d) Next octet defines length of exponent */
    if (lenE == 4) {
      lenE = *p;
      p++;
      len--;
      if (lenE == 0 || lenE >= 3) {
        /* "the third up to the (X plus 3)th (inclusive) contents octets encode
         * the value of the exponent as a two's complement binary number; the
         * value of X shall be at least one; the first nine bits of the
         * transmitted exponent shall not be all zeros or all ones."
         * The last part means that the exponent could not be representable
         * as a two's complement number using fewer octets. If there are
         * three octets, that means that the exponent must be sufficiently
         * large as not to fit in a IEEE 754 double precision floating point
         * (exponent offset binary width 11) or even a quadruple precision
         * binary128 (exponent offset binary width 15), or for that matter,
         * in an IBM double-precision/long hexadecimal floating point.
         *
         * Note that if lenE is 1 or 2 here this is not the smallest encoding
         * as 8.5.7.4 a) or b) could have been used, so it is still invalid
         * in CER, DER, or PER.
         */
        if (lenE == 0) {
          *err = EINVAL;
        } else if (lenE >= 3) {
          if (lenE > len) {
            *err = ERANGE;
          } else {
            val = asn1_get_overflow(*p, S);
          }
          *err = ERANGE;
        }
        return val;
      }
    } else {
      lenE++; // Make lenE the number of octets of the exponent
      /* Note that in BER c) does not require that the leading octet is not
       * all zeros or all ones, unlike d), so it might not overflow even if
       * the number of exponent octets is 3. */
    }

    /* Ensure the buffer len and its content are coherent */
    if (lenE > len) {
      *err = EINVAL;
      return val;
    }

    switch (lenE) {
    case 1:
      E = ws_sign_ext32(pntohu8(p), 8);
      break;
    case 2:
      E = ws_sign_ext32(pntohu16(p), 16);
      break;
    case 3:
      E = ws_sign_ext32(pntohu24(p), 24);
      break;
    default:
      ws_assert_not_reached();
    }

    p += lenE;

    /* 8.5.7.5 "The remaining contents octets encode the value of the integer
     * N as an unsigned binary number." */
    lenN = len - lenE;

    /* we can't handle integers > 64 bits, but that's ok, as no double precision
     * floating format can handle that much precision by definition. */
    /* Take the fraction from the first 8 octets and then use the length of the
     * remaining octets to adjust the exponent, losing the excess precision.
     * If the first octet is all zeros, which is allowed in BER, sigh, NOTE 1,
     * we should skip past it and any other all zero octets, but we don't.
     * We also ideally should set floating point exception FE_EXACT or an
     * errno substitute. */
    if (lenN > 8) {
      // Store the excess precision in bits
      if (ckd_mul(&exp, 8, lenN - 8)) {
        // Wow. Really?
        val = S * HUGE_VAL;
        *err = ERANGE;
        return val;
      }
      lenN = 8;
    }

    for (i=0; i<lenN; i++) {
      N = (N<<8) | *p;
      p++;
    }
    /* Since E is never larger than 24 bits, B no larger than 4, B*E + F
     * doesn't overflow an int. */
    if (ckd_add(&exp, exp, B*E + F)) {
      val = S * HUGE_VAL;
      *err = ERANGE;
    } else {
#ifndef _MSC_VER
      /* According to the C standard (7.6.1), #pragma STDC FENV_ACCESS ON can
       * appear at the start of a compound statement (i.e., here), and then
       * it is restored to its previous state. GCC doesn't support the pragma
       * and will warn about an unknown pragma. Luckily it doesn't need it
       * either, but some compilers might. */
      DIAG_OFF(unknown-pragmas)
      #pragma STDC FENV_ACCESS ON
#endif
      errno = 0;
      feclearexcept(FE_ALL_EXCEPT);
      val = ldexp((double) S * N, exp);
      if (errno || fetestexcept(FE_OVERFLOW | FE_UNDERFLOW)) {
        *err = ERANGE;
      }
#ifndef _MSC_VER
      DIAG_ON(unknown-pragmas)
#endif
    }
  } else if (octet & 0x40) {  /* SpecialRealValue */
    switch (octet & 0x3F) {
      case 0x00: val = HUGE_VAL; break;
      case 0x01: val = -HUGE_VAL; break;
      case 0x02: val = NAN; break;
      case 0x03: val = -0.0; break; /* Yes, negative 0 is different. */
      default:
        *err = EINVAL;
        break;
    }
  } else {  /* decimal encoding */
    char *buf;

    buf = g_strndup((const char*)p, len);
    /* g_ascii_strtod resets errno and returns ERANGE as appropriate */
    val = g_ascii_strtod(buf, NULL);
    if (errno == ERANGE) {
      *err = ERANGE;
    } else if (val == 0.0) {
      /* Since 0.0 "shall" be encoded with no contents octets (8.5.2), (and
       * minus 0 per 8.5.9) a return value of 0.0 must be a failed conversion
       * or where a zero was encoded with decimal encoding in violation of
       * the specification, and thus EINVAL is appropriate. */
      *err = EINVAL;
    }
    g_free(buf);
  }

  return val;
}

#ifdef _MSC_VER
#pragma float_control(pop)
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
