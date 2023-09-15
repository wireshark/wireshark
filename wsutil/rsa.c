/* rsa.c
 *
 * Functions for RSA private key reading and use
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "rsa.h"
#include "filesystem.h"
#include "file_util.h"
#include <errno.h>
#include <wsutil/wslog.h>


#ifdef HAVE_LIBGNUTLS

#include <gnutls/abstract.h>
#include <gnutls/pkcs12.h>

/* RSA private key file processing {{{ */
#define RSA_PARS 6
gcry_sexp_t
rsa_privkey_to_sexp(gnutls_x509_privkey_t priv_key, char **err)
{
    gnutls_datum_t rsa_datum[RSA_PARS]; /* m, e, d, p, q, u */
    size_t         tmp_size;
    gcry_error_t   gret;
    gcry_sexp_t    rsa_priv_key = NULL;
    int            i;
    gcry_mpi_t     rsa_params[RSA_PARS];
    *err = NULL;

    /* RSA get parameter */
    if (gnutls_x509_privkey_export_rsa_raw(priv_key,
                &rsa_datum[0],
                &rsa_datum[1],
                &rsa_datum[2],
                &rsa_datum[3],
                &rsa_datum[4],
                &rsa_datum[5])  != 0) {
        *err = g_strdup("can't export rsa param (is a rsa private key file ?!?)");
        return NULL;
    }

    /* convert each rsa parameter to mpi format*/
    for(i=0; i<RSA_PARS; i++) {
        gret = gcry_mpi_scan(&rsa_params[i], GCRYMPI_FMT_USG, rsa_datum[i].data, rsa_datum[i].size,&tmp_size);
        /* these buffers were allocated by gnutls_x509_privkey_export_rsa_raw() */
        g_free(rsa_datum[i].data);
        if (gret != 0) {
            *err = ws_strdup_printf("can't convert m rsa param to int (size %d)", rsa_datum[i].size);
            return NULL;
        }
    }

    /* libgcrypt expects p < q, and gnutls might not return it as such, depending on gnutls version and its crypto backend */
    if (gcry_mpi_cmp(rsa_params[3], rsa_params[4]) > 0)
    {
        /* p, q = q, p */
        gcry_mpi_swap(rsa_params[3], rsa_params[4]);
        /* due to swapping p and q, u = p^-1 mod p which happens to be needed. */
    }
    /* libgcrypt expects u = p^-1 mod q (for OpenPGP), but the u parameter
     * says u = q^-1 mod p. Recompute u = p^-1 mod q. Do this unconditionally as
     * at least GnuTLS 2.12.23 computes an invalid value. */
    gcry_mpi_invm(rsa_params[5], rsa_params[3], rsa_params[4]);

    if  (gcry_sexp_build( &rsa_priv_key, NULL,
                "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))", rsa_params[0],
                rsa_params[1], rsa_params[2], rsa_params[3], rsa_params[4],
                rsa_params[5]) != 0) {
        *err = g_strdup("can't build rsa private key s-exp");
        return NULL;
    }

    for (i=0; i< 6; i++)
        gcry_mpi_release(rsa_params[i]);
    return rsa_priv_key;
}

gnutls_x509_privkey_t
rsa_load_pem_key(FILE *fp, char **err)
{
    /* gnutls makes our work much harder, since we have to work internally with
     * s-exp formatted data, but PEM loader exports only in "gnutls_datum_t"
     * format, and a datum -> s-exp conversion function does not exist.
     */
    gnutls_x509_privkey_t priv_key;
    gnutls_datum_t        key;
    ws_statb64            statbuf;
    int                   ret;
    unsigned              bytes;
    *err = NULL;

    if (ws_fstat64(ws_fileno(fp), &statbuf) == -1) {
        *err = ws_strdup_printf("can't ws_fstat64 file: %s", g_strerror(errno));
        return NULL;
    }
    if (S_ISDIR(statbuf.st_mode)) {
        *err = g_strdup("file is a directory");
        errno = EISDIR;
        return NULL;
    }
    if (S_ISFIFO(statbuf.st_mode)) {
        *err = g_strdup("file is a named pipe");
        errno = EINVAL;
        return NULL;
    }
    if (!S_ISREG(statbuf.st_mode)) {
        *err = g_strdup("file is not a regular file");
        errno = EINVAL;
        return NULL;
    }
    /* XXX - check for a too-big size */
    /* load all file contents into a datum buffer*/
    key.data = (unsigned char *)g_malloc((size_t)statbuf.st_size);
    key.size = (int)statbuf.st_size;
    bytes = (unsigned) fread(key.data, 1, key.size, fp);
    if (bytes < key.size) {
        if (bytes == 0 && ferror(fp)) {
            *err = ws_strdup_printf("can't read from file %d bytes, got error %s",
                    key.size, g_strerror(errno));
        } else {
            *err = ws_strdup_printf("can't read from file %d bytes, got %d",
                    key.size, bytes);
        }
        g_free(key.data);
        return NULL;
    }

    /* init private key data*/
    gnutls_x509_privkey_init(&priv_key);

    /* import PEM data*/
    if ((ret = gnutls_x509_privkey_import(priv_key, &key, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
        *err = ws_strdup_printf("can't import pem data: %s", gnutls_strerror(ret));
        g_free(key.data);
        gnutls_x509_privkey_deinit(priv_key);
        return NULL;
    }

    if (gnutls_x509_privkey_get_pk_algorithm(priv_key) != GNUTLS_PK_RSA) {
        *err = g_strdup("private key public key algorithm isn't RSA");
        g_free(key.data);
        gnutls_x509_privkey_deinit(priv_key);
        return NULL;
    }

    g_free(key.data);

    return priv_key;
}

static const char *
BAGTYPE(gnutls_pkcs12_bag_type_t x) {
    switch (x) {
        case GNUTLS_BAG_EMPTY:               return "Empty";
        case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY: return "PKCS#8 Encrypted key";
        case GNUTLS_BAG_PKCS8_KEY:           return "PKCS#8 Key";
        case GNUTLS_BAG_CERTIFICATE:         return "Certificate";
        case GNUTLS_BAG_CRL:                 return "CRL";
        case GNUTLS_BAG_ENCRYPTED:           return "Encrypted";
        case GNUTLS_BAG_UNKNOWN:             return "Unknown";
        default:                             return "<undefined>";
    }
}

gnutls_x509_privkey_t
rsa_load_pkcs12(FILE *fp, const char *cert_passwd, char **err)
{
    int                       i, j, ret;
    int                       rest;
    unsigned char            *p;
    gnutls_datum_t            data;
    gnutls_pkcs12_bag_t       bag = NULL;
    size_t                    len;

    gnutls_pkcs12_t       rsa_p12  = NULL;

    gnutls_x509_privkey_t     priv_key = NULL;
    *err = NULL;

    rest = 4096;
    data.data = (unsigned char *)g_malloc(rest);
    data.size = rest;
    p = data.data;
    while ((len = fread(p, 1, rest, fp)) > 0) {
        p += len;
        rest -= (int) len;
        if (!rest) {
            rest = 1024;
            data.data = (unsigned char *)g_realloc(data.data, data.size + rest);
            p = data.data + data.size;
            data.size += rest;
        }
    }
    data.size -= rest;
    if (!feof(fp)) {
        *err = g_strdup("Error during certificate reading.");
        g_free(data.data);
        return NULL;
    }

    ret = gnutls_pkcs12_init(&rsa_p12);
    if (ret < 0) {
        *err = ws_strdup_printf("gnutls_pkcs12_init(&st_p12) - %s", gnutls_strerror(ret));
        g_free(data.data);
        return NULL;
    }

    /* load PKCS#12 in DER or PEM format */
    ret = gnutls_pkcs12_import(rsa_p12, &data, GNUTLS_X509_FMT_DER, 0);
    if (ret < 0) {
        ret = gnutls_pkcs12_import(rsa_p12, &data, GNUTLS_X509_FMT_PEM, 0);
        if (ret < 0) {
            *err = ws_strdup_printf("could not load PKCS#12 in DER or PEM format: %s", gnutls_strerror(ret));
        }
    }
    g_free(data.data);
    if (ret < 0) {
        gnutls_pkcs12_deinit(rsa_p12);
        return NULL;
    }

    ws_debug("grsa_privkey_to_sexp: PKCS#12 imported");

    /* TODO: Use gnutls_pkcs12_simple_parse, since 3.1.0 (August 2012) */
    for (i=0; ; i++) {
        gnutls_pkcs12_bag_type_t  bag_type;

        ret = gnutls_pkcs12_bag_init(&bag);
        if (ret < 0) {
            *err = ws_strdup_printf("gnutls_pkcs12_bag_init failed: %s",
                                   gnutls_strerror(ret));
            goto done;
        }

        ret = gnutls_pkcs12_get_bag(rsa_p12, i, bag);
        if (ret < 0) {
            *err = ws_strdup_printf("gnutls_pkcs12_get_bag failed: %s",
                                   gnutls_strerror(ret));
            goto done;
        }

        for (j=0; j<gnutls_pkcs12_bag_get_count(bag); j++) {

            ret = gnutls_pkcs12_bag_get_type(bag, j);
            if (ret < 0) {
                *err = ws_strdup_printf("gnutls_pkcs12_bag_get_type failed: %s",
                                       gnutls_strerror(ret));
                goto done;
            }
            bag_type = (gnutls_pkcs12_bag_type_t)ret;
            if (bag_type >= GNUTLS_BAG_UNKNOWN) {
                *err = ws_strdup_printf("gnutls_pkcs12_bag_get_type returned unknown bag type %u",
                                       ret);
                goto done;
            }
            ws_debug("Bag %d/%d: %s", i, j, BAGTYPE(bag_type));
            if (bag_type == GNUTLS_BAG_ENCRYPTED) {
                ret = gnutls_pkcs12_bag_decrypt(bag, cert_passwd);
                if (ret == 0) {
                    ret = gnutls_pkcs12_bag_get_type(bag, j);
                    if (ret < 0) {
                        *err = ws_strdup_printf("gnutls_pkcs12_bag_get_type failed: %s",
                                               gnutls_strerror(ret));
                        goto done;
                    }
                    bag_type = (gnutls_pkcs12_bag_type_t)ret;
                    if (bag_type >= GNUTLS_BAG_UNKNOWN) {
                        *err = ws_strdup_printf("gnutls_pkcs12_bag_get_type returned unknown bag type %u",
                                               ret);
                        goto done;
                    }
                    ws_debug("Bag %d/%d decrypted: %s", i, j, BAGTYPE(bag_type));
                }
            }

            ret = gnutls_pkcs12_bag_get_data(bag, j, &data);
            if (ret < 0) {
                *err = ws_strdup_printf("gnutls_pkcs12_bag_get_data failed: %s",
                                       gnutls_strerror(ret));
                goto done;
            }

            switch (bag_type) {

                case GNUTLS_BAG_PKCS8_KEY:
                case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
                {
                    gnutls_x509_privkey_t rsa_pkey;

                    ret = gnutls_x509_privkey_init(&rsa_pkey);
                    if (ret < 0) {
                        *err = ws_strdup_printf("gnutls_x509_privkey_init failed: %s", gnutls_strerror(ret));
                        goto done;
                    }
                    ret = gnutls_x509_privkey_import_pkcs8(rsa_pkey, &data, GNUTLS_X509_FMT_DER, cert_passwd,
                            (bag_type==GNUTLS_BAG_PKCS8_KEY) ? GNUTLS_PKCS_PLAIN : 0);
                    if (ret < 0) {
                        *err = ws_strdup_printf("Can not decrypt private key - %s", gnutls_strerror(ret));
                        gnutls_x509_privkey_deinit(rsa_pkey);
                        goto done;
                    }

                    if (gnutls_x509_privkey_get_pk_algorithm(rsa_pkey) != GNUTLS_PK_RSA) {
                        *err = g_strdup("private key public key algorithm isn't RSA");
                        gnutls_x509_privkey_deinit(rsa_pkey);
                        goto done;
                    }

                    /* Private key found, return it. */
                    priv_key = rsa_pkey;
                    goto done;
                }

                default: ;
            }
        }  /* j */

        gnutls_pkcs12_bag_deinit(bag);
        bag = NULL;
    }  /* i */

done:
    if (bag) {
        gnutls_pkcs12_bag_deinit(bag);
    }
    if (!priv_key) {
        /*
         * We failed.  If we didn't fail with an error, we failed because
         * we found no PKCS8 key and fell out of the loop; report that
         * error.
         */
        if (*err == NULL)
            *err = g_strdup("no PKCS8 key found");
    }
    gnutls_pkcs12_deinit(rsa_p12);

    return priv_key;
}

void
rsa_private_key_free(void * key)
{
    gcry_sexp_release((gcry_sexp_t) key);
}

#else /* ! defined(HAVE_LIBGNUTLS) */

void
rsa_private_key_free(void * key _U_)
{
}

#endif /* HAVE_LIBGNUTLS */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
