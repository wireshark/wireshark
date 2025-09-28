/*
 * wslua_gcrypt.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2025, Bartis Csaba <bracsek@bracsek.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "wslua.h"

/* WSLUA_MODULE Gcrypt Gcrypt symmetric cipher functions

  A <<lua_class_GcryptCipher,`GcryptCipher`>> object represents gcypt symmetric cipher in Lua.

  The cipher functions are used for symmetrical cryptography, i.e. cryptography using a shared key.
  The programming model follows an open/process/close paradigm and is in that similar to
  other building blocks provided by Libgcrypt.

  There is an example after the <<lua_fn_gcryptcipher_authenticate_abuf_,`GcryptCipher.authenticate`>> function.

 */

WSLUA_CLASS_DEFINE(GcryptCipher,FAIL_ON_NULL("GcryptCipher"));

WSLUA_CONSTRUCTOR GcryptCipher_open(lua_State* L) {
    /*
    Creates a new <<lua_class_GcryptCipher,`GcryptCipher`>> object.

    This object uses the symmetric cipher functions to encrypt or decrypt data.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    ----
    */
#define WSLUA_ARG_GcryptCipher_open_ALGORITHM 1 /* Select the algorithm for this cipher. */
#define WSLUA_ARG_GcryptCipher_open_MODE 2 /* Select mode for this algorithm */
#define WSLUA_ARG_GcryptCipher_open_FLAGS 3 /* Set the flags for this cipher */
    int algo = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_open_ALGORITHM);
    int mode = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_open_MODE);
    int flags = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_open_FLAGS);
    GcryptCipher gcry_cipher = (GcryptCipher)g_malloc(sizeof(gcry_cipher_hd_t));
    gcry_error_t err = gcry_cipher_open(gcry_cipher, algo, mode, flags);
    if (err) {
        g_free(gcry_cipher);
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    pushGcryptCipher(L, gcry_cipher);
    WSLUA_RETURN(1); /* The new GcryptCipher object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int GcryptCipher__gc(lua_State* L) {
    GcryptCipher gcry_cipher = toGcryptCipher(L,1);
    if (!gcry_cipher) return 0;
    gcry_cipher_close(*gcry_cipher);
    g_free(gcry_cipher);
    return 0;
}

WSLUA_METHOD GcryptCipher_ctl(lua_State* L) {
    /*
    Perform various operations on the cipher object H.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    -- CFB mode synchronization
    cipher:ctl(GCRYCTL_CFB_SYNC, ByteArray.new())
    -- enabling CBC-MAC mode
    cipher:ctl(GCRYCTL_SET_CBC_MAC, ByteArray.new())
    ----
    */
#define WSLUA_ARG_GcryptCipher_ctl_CMD 2 /* Command identifier. */
#define WSLUA_ARG_GcryptCipher_ctl_BUFFER 3 /* <<lua_class_ByteArray,`ByteArray`>> as buffer and buffer length. */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    int cmd = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_ctl_CMD);
    ByteArray buffer = checkByteArray(L, WSLUA_ARG_GcryptCipher_ctl_BUFFER);
    gcry_error_t err = gcry_cipher_ctl(*gcry_cipher, cmd, buffer->data, (size_t) buffer->len);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    WSLUA_RETURN(0);
}

WSLUA_METHOD GcryptCipher_info(lua_State* L) {
    /*
    Retrieve various information about the cipher object H.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)
    -- Get the tag length of GCM.
    local userdata, nbytes =  cipher:info(GCRYCTL_GET_TAGLEN, NULL, 1)
    print("Tag length: " .. tostring(nbytes))
    ----
    */
#define WSLUA_ARG_GcryptCipher_info_WHAT 2 /* Select what info will be returned. */
#define WSLUA_ARG_GcryptCipher_info_BUFFER_SIZE 3 /* Buffer size or NULL */
#define WSLUA_ARG_GcryptCipher_info_NBYTES 4 /* Nbytes integer or NULL */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    int what = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_info_WHAT);
    size_t *pnbytes = NULL;
    char* pbuffer = NULL;
    ByteArray ba = g_byte_array_new();
    size_t nbytes = 0;
    if (lua_isinteger(L, WSLUA_ARG_GcryptCipher_info_BUFFER_SIZE)) {
        g_byte_array_set_size(ba, (int) luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_info_BUFFER_SIZE));
        pbuffer = ba->data;
    }
    if (lua_isinteger(L, WSLUA_ARG_GcryptCipher_info_NBYTES)) {
        nbytes = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_info_NBYTES);
        pnbytes = (size_t *) &nbytes;
    }
    gcry_error_t err = gcry_cipher_info(*gcry_cipher, what, pbuffer, pnbytes);
    if (err) {
        g_byte_array_free(ba, TRUE);
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    pushByteArray(L, ba);
    if (pnbytes != NULL) {
        lua_pushinteger(L, (int) nbytes);
    }
    else {
        lua_pushinteger(L, 0);
    }
    WSLUA_RETURN(2);
}

WSLUA_METHOD GcryptCipher_encrypt(lua_State* L) {
    /*
    Encrypt the plaintext of size INLEN in IN using the cipher handle H
    into the buffer OUT which has an allocated length of OUTSIZE.  For
    most algorithms it is possible to pass NULL for in and do a in-place
    encryption of the data returned in a  <<lua_class_ByteArray,`ByteArray`>>.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    cipher:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    local encrypted = cipher:encrypt(NULL, ByteArray.new("000102030405060708090a0b0c0d0e0f"))
    print("Encrypted: " .. encrypted:tohex())
    -- in place encryption
    cipher:ctl(GCRYCTL_RESET, ByteArray.new())
    local data = ByteArray.new("000102030405060708090a0b0c0d0e0f")
    cipher:encrypt(data)
    print("In-place encrypted: " .. data:tohex())
    ----
    */
#define WSLUA_ARG_GcryptCipher_encrypt_OUT 2 /* <<lua_class_ByteArray,`ByteArray`>> with data for in-place encryption or NULL */
#define WSLUA_OPTARG_GcryptCipher_encrypt_IN 3 /* <<lua_class_ByteArray,`ByteArray`>> with data or NULL */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    char* pin = NULL;
    char* pout = NULL;
    size_t in_length = 0;
    size_t out_length = 0;
    ByteArray bain = NULL;
    ByteArray baout = NULL;
    if (!isByteArray(L, WSLUA_OPTARG_GcryptCipher_encrypt_IN) &&
        !isByteArray(L, WSLUA_ARG_GcryptCipher_encrypt_OUT)) {
        return lua_error(L);
    }
    if (isByteArray(L, WSLUA_OPTARG_GcryptCipher_encrypt_IN)) {
        bain = checkByteArray(L, WSLUA_OPTARG_GcryptCipher_encrypt_IN);
        pin = bain->data;
        in_length = (size_t) bain->len;
    }
    if (isByteArray(L, WSLUA_ARG_GcryptCipher_encrypt_OUT)) {
        baout = checkByteArray(L, WSLUA_ARG_GcryptCipher_encrypt_OUT);
        pout = baout->data;
        out_length = (size_t) baout->len;
        bain = NULL;
        pin = NULL;
        in_length = (size_t) 0;
    } else {
        baout = g_byte_array_new();
        if (bain != NULL) {
            g_byte_array_set_size(baout, (int) bain->len);
        }
        pout = baout->data;
        out_length = (size_t) baout->len;
    }
    gcry_error_t err = gcry_cipher_encrypt(*gcry_cipher, pout, out_length, pin, in_length);
    if (err) {
        if (bain != NULL) {
            g_byte_array_free(baout, TRUE);
        }
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    if (bain != NULL) {
        pushByteArray(L, baout);
        WSLUA_RETURN(1);
    } else {
        WSLUA_RETURN(0);
    }
}

WSLUA_METHOD GcryptCipher_decrypt(lua_State* L) {
    /*
    The counterpart to gcry_cipher_encrypt.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    cipher:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    local decrypted = cipher:decrypt(NULL, ByteArray.new("E27FC30A38E17B6BB7E67AFF2800792F"))
    print("Decrypted: " .. decrypted:tohex())
    -- in place decryption
    cipher:ctl(GCRYCTL_RESET, ByteArray.new())
    local data = ByteArray.new("E27FC30A38E17B6BB7E67AFF2800792F")
    cipher:decrypt(data)
    print("In-place decrypted: " .. data:tohex())
    ----
    */
#define WSLUA_ARG_GcryptCipher_decrypt_OUT 2 /* <<lua_class_ByteArray,`ByteArray`>> with data for in-place decryption or NULL */
#define WSLUA_OPTARG_GcryptCipher_decrypt_IN 3 /* <<lua_class_ByteArray,`ByteArray`>> with data or NULL */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    if (!isByteArray(L, WSLUA_OPTARG_GcryptCipher_decrypt_IN) &&
        !isByteArray(L, WSLUA_ARG_GcryptCipher_decrypt_OUT)) {
        return lua_error(L);
    }
    char* pin = NULL;
    char* pout = NULL;
    size_t in_length = 0;
    size_t out_length = 0;
    ByteArray bain = NULL;
    ByteArray baout = NULL;
    if (isByteArray(L, WSLUA_OPTARG_GcryptCipher_decrypt_IN)) {
        bain = checkByteArray(L, WSLUA_OPTARG_GcryptCipher_decrypt_IN);
        pin = bain->data;
        in_length = (size_t) bain->len;
    }
    if (isByteArray(L, WSLUA_ARG_GcryptCipher_decrypt_OUT)) {
        baout = checkByteArray(L, WSLUA_ARG_GcryptCipher_decrypt_OUT);
        pout = baout->data;
        out_length = (size_t) baout->len;
        bain = NULL;
        pin = NULL;
        in_length = (size_t) 0;
    } else {
        baout = g_byte_array_new();
        if (bain != NULL) {
            g_byte_array_set_size(baout, (int) bain->len);
        }
        pout = baout->data;
        out_length = (size_t) baout->len;
    }
    gcry_error_t err = gcry_cipher_decrypt(*gcry_cipher, pout, out_length, pin, in_length);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    if (bain != NULL) {
        pushByteArray(L, baout);
        WSLUA_RETURN(1);
    } else {
        WSLUA_RETURN(0);
    }
}

WSLUA_METHOD GcryptCipher_setkey(lua_State* L) {
    /*
    Set KEY of length KEYLEN bytes for the cipher handle HD.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    cipher:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    ----
    */
#define WSLUA_ARG_GcryptCipher_setkey_KEY 2 /* <<lua_class_ByteArray,`ByteArray`>> as buffer and buffer length. */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    ByteArray buffer = checkByteArray(L, WSLUA_ARG_GcryptCipher_setkey_KEY);
    gcry_error_t err = gcry_cipher_setkey(*gcry_cipher, buffer->data, (size_t) buffer->len);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    WSLUA_RETURN(0);
}

WSLUA_METHOD GcryptCipher_setiv(lua_State* L) {
    /*
    Set initialization vector IV of length IVLEN for the cipher handle HD.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    cipher:setiv(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    ----
    */
#define WSLUA_ARG_GcryptCipher_setiv_IV 2 /* <<lua_class_ByteArray,`ByteArray`>> as buffer and buffer length. */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    ByteArray buffer = checkByteArray(L, WSLUA_ARG_GcryptCipher_setiv_IV);
    gcry_error_t err = gcry_cipher_setiv(*gcry_cipher, buffer->data, (size_t) buffer->len);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    WSLUA_RETURN(0);
}

WSLUA_METHOD GcryptCipher_authenticate(lua_State* L) {
    /*
    Provide additional authentication data for AEAD modes/ciphers.

    ===== Example

    [source,lua]
    ----
    local cipher_encrypt = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)
    cipher_encrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    cipher_encrypt:setiv(ByteArray.new("01020304050607080102030405060708"))

    local cipher_decrypt = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)
    cipher_decrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    cipher_decrypt:setiv(ByteArray.new("01020304050607080102030405060708"))

    print("Plain data: " .. ByteArray.new("000102030405060708090a0b0c0d0e0f"):tohex())
    cipher_encrypt:authenticate(ByteArray.new("55667788"))
    local encrypted = cipher_encrypt:encrypt(NULL,
        ByteArray.new("000102030405060708090a0b0c0d0e0f"))
    local tag = cipher_encrypt:gettag()
    print("Encrypted data: " .. encrypted:tohex())
    print("Tag: " .. tag:tohex())

    cipher_decrypt:authenticate(ByteArray.new("55667788"))
    local decrypted = cipher_decrypt:decrypt(NULL, encrypted)
    local result, errstring = cipher_decrypt:checktag(tag)
    if (result == 0) then
        print("Message ok!")
        print("Decrypted data: " .. decrypted:tohex())
    else
        print("Manipulated message: " .. errstring)
    end
    ----
    */
#define WSLUA_ARG_GcryptCipher_authenticate_ABUF 2 /* <<lua_class_ByteArray,`ByteArray`>> as authentication data. */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    ByteArray buffer = checkByteArray(L, WSLUA_ARG_GcryptCipher_authenticate_ABUF);
    gcry_error_t err = gcry_cipher_authenticate(*gcry_cipher, buffer->data, (size_t) buffer->len);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    WSLUA_RETURN(0);
}

WSLUA_METHOD GcryptCipher_gettag(lua_State* L) {
    /*
    Get authentication tag for AEAD modes/ciphers.
    */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    ByteArray ba = g_byte_array_new();
    size_t tag_size = 0;
    gcry_error_t err = gcry_cipher_info(*gcry_cipher, GCRYCTL_GET_TAGLEN, NULL, &tag_size);
    if (!err) {
        g_byte_array_set_size(ba, (int)tag_size);
        err = gcry_cipher_gettag(*gcry_cipher, ba->data, (size_t) ba->len);
    }
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    pushByteArray(L, ba);
    WSLUA_RETURN(1);
}

WSLUA_METHOD GcryptCipher_checktag(lua_State* L) {
    /*
    Check authentication tag for AEAD modes/ciphers.
    */
#define WSLUA_ARG_GcryptCipher_checktag_TAG 2 /* <<lua_class_ByteArray,`ByteArray`>> as authentication tag to check. */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    ByteArray buffer = checkByteArray(L, WSLUA_ARG_GcryptCipher_checktag_TAG);
    gcry_error_t err = gcry_cipher_checktag(*gcry_cipher, buffer->data, (size_t) buffer->len);
    lua_pushinteger(L, err);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        WSLUA_RETURN(2);
    }
    WSLUA_RETURN(1);
}

WSLUA_METHOD GcryptCipher_setctr(lua_State* L) {
    /*
    Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
    block size length, or (NULL,0) to set the CTR to the all-zero block.

    ===== Example

    [source,lua]
    ----
    local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
    cipher:setctr(ByteArray.new("000102030405060708090A0B0C0D0E0F"), 16)
    ----
    */
#define WSLUA_ARG_GcryptCipher_setctr_CTR 2 /* <<lua_class_ByteArray,`ByteArray`>> with ctr or NULL */
#define WSLUA_ARG_GcryptCipher_setctr_CTRLEN 3 /* CTR Length */
    GcryptCipher gcry_cipher = checkGcryptCipher(L, 1);
    char* pctr = NULL;
    ByteArray ba = NULL;
    int ctrlen = 0;
    if (isByteArray(L, WSLUA_ARG_GcryptCipher_setctr_CTR)) {
        ba = checkByteArray(L, WSLUA_ARG_GcryptCipher_setctr_CTR);
        pctr = ba->data;
    }
    if (lua_isinteger(L, WSLUA_ARG_GcryptCipher_setctr_CTRLEN)) {
        ctrlen = (int)luaL_checkinteger(L, WSLUA_ARG_GcryptCipher_setctr_CTRLEN);
    }
    gcry_error_t err = gcry_cipher_setctr(*gcry_cipher, pctr, ctrlen);
    if (err) {
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    WSLUA_RETURN(0);
}

WSLUA_FUNCTION wslua_gcry_cipher_algo_info(lua_State* L) {
     /*
    Retrieve various information about the cipher algorithm ALGO.

    ===== Example

    [source,lua]
    ----
    local userdata, nbytes = gcry_cipher_algo_info(GCRY_CIPHER_AES, GCRYCTL_GET_KEYLEN, NULL, 0)
    print("Key length: " .. nbytes)
    local userdata, nbytes = gcry_cipher_algo_info(GCRY_CIPHER_AES, GCRYCTL_GET_BLKLEN, NULL, 0)
    print("Block length: " .. nbytes)
    local status = gcry_cipher_algo_info(GCRY_CIPHER_AES, GCRYCTL_TEST_ALGO)
    if (status == 0) then
      print("GCRY_CIPHER_AES - Supported.")
    else
      print("GCRY_CIPHER_AES - Not supported.")
    end
    ----
    */
#define WSLUA_ARG_gcry_cipher_algo_info_ALGORITHM 1 /* Select the algorithm for this function. */
#define WSLUA_ARG_gcry_cipher_algo_info_WHAT 2 /* Select the algorithm for this function. */
#define WSLUA_OPTARG_gcry_cipher_algo_info_BUFFER_SIZE 3 /* Buffer size or NULL, optional only if nbytes not present. */
#define WSLUA_OPTARG_gcry_cipher_algo_info_NBYTES 4 /* Nbytes integer or NULL, optional. */
    int algo = (int)luaL_checkinteger(L, WSLUA_ARG_gcry_cipher_algo_info_ALGORITHM);
    int what = (int)luaL_checkinteger(L, WSLUA_ARG_gcry_cipher_algo_info_WHAT);
    size_t *pnbytes = NULL;
    char* pbuffer = NULL;
    ByteArray ba = g_byte_array_new();
    size_t nbytes = 0;
    if (lua_isinteger(L, WSLUA_OPTARG_gcry_cipher_algo_info_BUFFER_SIZE)) {
        g_byte_array_set_size(ba, (int) luaL_checkinteger(L, WSLUA_OPTARG_gcry_cipher_algo_info_BUFFER_SIZE));
        pbuffer = ba->data;
    }
    if (lua_isinteger(L, WSLUA_OPTARG_gcry_cipher_algo_info_NBYTES)) {
        nbytes = (int)luaL_checkinteger(L, WSLUA_OPTARG_gcry_cipher_algo_info_NBYTES);
        pnbytes = (size_t *) &nbytes;
    }
    gcry_error_t err = gcry_cipher_algo_info(algo, what, pbuffer, pnbytes);
    if (what == GCRYCTL_TEST_ALGO) {
        g_byte_array_free(ba, TRUE);
        lua_pushinteger(L, err);
        WSLUA_RETURN(1);
    }
    if (err) {
        g_byte_array_free(ba, TRUE);
        lua_pushstring(L, gcry_strerror(err));
        return lua_error(L);
    }
    pushByteArray(L, ba);
    if (!err || (pnbytes != NULL)) {
        lua_pushinteger(L, (int) nbytes);
    }
    else {
        lua_pushinteger(L, -1);
    }
    WSLUA_RETURN(2);
}

WSLUA_FUNCTION wslua_gcry_cipher_algo_name(lua_State* L) {
    /*
    Map the cipher algorithm whose ID is contained in ALGORITHM to a
    string representation of the algorithm name.  For unknown algorithm
    IDs this function returns "?".

    ===== Example

    [source,lua]
    ----
    local name = gcry_cipher_algo_name(GCRY_CIPHER_AES)
    print(name)
    ----
    */
#define WSLUA_ARG_gcry_cipher_algo_name_ALGORITHM 1 /* Algorithm id for this function. */
    int algo = (int)luaL_checkinteger(L, WSLUA_ARG_gcry_cipher_algo_name_ALGORITHM);
    lua_pushstring(L, gcry_cipher_algo_name (algo));
    WSLUA_RETURN(1);
}

WSLUA_FUNCTION wslua_gcry_cipher_map_name(lua_State* L) {
    /*
    Map the algorithm name NAME to an cipher algorithm ID.  Return 0 if
    the algorithm name is not known.

    ===== Example

    [source,lua]
    ----
    local id = gcry_cipher_map_name("AES")
    print(id)
    ----
    */
#define WSLUA_ARG_gcry_cipher_map_name_ALGORITHM 1 /* Algorithm name for this function. */
    const char* algo = luaL_checkstring(L, WSLUA_ARG_gcry_cipher_map_name_ALGORITHM);
    lua_pushinteger(L, gcry_cipher_map_name(algo));
    WSLUA_RETURN(1);
}

WSLUA_FUNCTION wslua_gcry_cipher_mode_from_oid(lua_State* L) {
    /*
    Given an ASN.1 object identifier in standard IETF dotted decimal
    format in STRING, return the encryption mode associated with that
    OID or 0 if not known or applicable.

    ===== Example

    [source,lua]
    ----
    local mode = gcry_cipher_mode_from_oid("2.16.840.1.101.3.4.1.2")
    -- reurned value 3 means GCRY_CIPHER_MODE_CBC
    print(mode)
    ----
    */
#define WSLUA_ARG_gcry_cipher_mode_from_oid_STRING 1 /* ASN.1 object identifier as STRING. */
    const char* asn1 = luaL_checkstring(L, WSLUA_ARG_gcry_cipher_mode_from_oid_STRING);
    lua_pushinteger(L, gcry_cipher_mode_from_oid(asn1));
    WSLUA_RETURN(1);
}

WSLUA_FUNCTION wslua_gcry_cipher_get_algo_keylen(lua_State* L) {
    /*
    Retrieve the key length in bytes used with algorithm A.

    ===== Example

    [source,lua]
    ----
    local length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES)
    print(length)
    ----
    */
#define WSLUA_ARG_gcry_cipher_get_algo_keylen_ALGORITHM 1 /* Algorithm id for this function. */
    int algo = (int)luaL_checkinteger(L, WSLUA_ARG_gcry_cipher_get_algo_keylen_ALGORITHM);
    lua_pushinteger(L, gcry_cipher_get_algo_keylen(algo));
    WSLUA_RETURN(1);
}

WSLUA_FUNCTION wslua_gcry_cipher_get_algo_blklen(lua_State* L) {
    /*
    Retrieve the block length in bytes used with algorithm A.

    ===== Example

    [source,lua]
    ----
    local length = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES)
    print(length)
    ----
    */
#define WSLUA_ARG_gcry_cipher_get_algo_blklen_ALGORITHM 1 /* Algorithm id for this function. */
    int algo = (int)luaL_checkinteger(L, WSLUA_ARG_gcry_cipher_get_algo_blklen_ALGORITHM);
    lua_pushinteger(L, gcry_cipher_get_algo_blklen(algo));
    WSLUA_RETURN(1);
}

WSLUA_METHODS GcryptCipher_methods[] = {
    WSLUA_CLASS_FNREG(GcryptCipher, open),
    WSLUA_CLASS_FNREG(GcryptCipher, ctl),
    WSLUA_CLASS_FNREG(GcryptCipher, info),
    WSLUA_CLASS_FNREG(GcryptCipher, encrypt),
    WSLUA_CLASS_FNREG(GcryptCipher, decrypt),
    WSLUA_CLASS_FNREG(GcryptCipher, setkey),
    WSLUA_CLASS_FNREG(GcryptCipher, setiv),
    WSLUA_CLASS_FNREG(GcryptCipher, authenticate),
    WSLUA_CLASS_FNREG(GcryptCipher, gettag),
    WSLUA_CLASS_FNREG(GcryptCipher, checktag),
    WSLUA_CLASS_FNREG(GcryptCipher, setctr),
    { NULL, NULL }
};

WSLUA_META GcryptCipher_meta[] = {
    { NULL, NULL }
};

int GcryptCipher_register(lua_State* L) {
    // cipher identifiers
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_NONE", 0);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_IDEA", 1);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_3DES", 2);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CAST5", 3);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_BLOWFISH", 4);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SAFER_SK128", 5);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_DES_SK", 6);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_AES", 7);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_AES192", 8);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_AES256", 9);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_TWOFISH", 10);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_ARCFOUR", 301);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_DES", 302);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_TWOFISH128", 303);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SERPENT128", 304);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SERPENT192", 305);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SERPENT256", 306);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_RFC2268_40", 307);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_RFC2268_128", 308);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SEED", 309);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CAMELLIA128", 310);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CAMELLIA192", 311);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CAMELLIA256", 312);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SALSA20", 313);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SALSA20R12", 314);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_GOST28147", 315);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CHACHA20", 316);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_GOST28147_MESH", 317);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SM4", 318);
    // mode identifiers
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_NONE", 0);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_ECB", 1);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_CFB", 2);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_CBC", 3);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_STREAM", 4);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_OFB", 5);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_CTR", 6);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_AESWRAP", 7);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_CCM", 8);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_GCM", 9);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_POLY1305", 10);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_OCB", 11);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_CFB8", 12);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_XTS", 13);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_MODE_EAX", 14);
    // cipher flags
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_SECURE", 1);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_ENABLE_SYNC", 2);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CBC_CTS", 4);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRY_CIPHER_CBC_MAC", 8);
    // cipher ctl identifiers
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_CFB_SYNC", 3);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_RESET", 4);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_FINALIZE", 5);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_KEYLEN", 6);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_BLKLEN", 7);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_TEST_ALGO", 8);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_IS_SECURE", 9);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ASNOID", 10);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_ENABLE_ALGO", 11);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_ALGO", 12);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DUMP_RANDOM_STATS", 13);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DUMP_SECMEM_STATS", 14);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ALGO_NPKEY", 15);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ALGO_NSKEY", 16);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ALGO_NSIGN", 17);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ALGO_NENCR", 18);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_VERBOSITY", 19);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_DEBUG_FLAGS", 20);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_CLEAR_DEBUG_FLAGS", 21);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_USE_SECURE_RNDPOOL", 22);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DUMP_MEMORY_STATS", 23);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_INIT_SECMEM", 24);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_TERM_SECMEM", 25);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_SECMEM_WARN", 27);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SUSPEND_SECMEM_WARN", 28);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_RESUME_SECMEM_WARN", 29);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DROP_PRIVS", 30);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_ENABLE_M_GUARD", 31);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_START_DUMP", 32);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_STOP_DUMP", 33);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_ALGO_USAGE", 34);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_IS_ALGO_ENABLED", 35);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_INTERNAL_LOCKING", 36);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_SECMEM", 37);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_INITIALIZATION_FINISHED", 38);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_INITIALIZATION_FINISHED_P", 39);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_ANY_INITIALIZATION_P", 40);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_CBC_CTS", 41);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_CBC_MAC", 42);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_ENABLE_QUICK_RANDOM", 44);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_RANDOM_SEED_FILE", 45);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_UPDATE_RANDOM_SEED_FILE", 46);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_THREAD_CBS", 47);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_FAST_POLL", 48);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_RANDOM_DAEMON_SOCKET", 49);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_USE_RANDOM_DAEMON", 50);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_FAKED_RANDOM_P", 51);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_RNDEGD_SOCKET", 52);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_PRINT_CONFIG", 53);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_OPERATIONAL_P", 54);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_FIPS_MODE_P", 55);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_FORCE_FIPS_MODE", 56);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SELFTEST", 57);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_HWF", 63);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_ENFORCED_FIPS_FLAG", 64);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_PREFERRED_RNG_TYPE", 65);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_CURRENT_RNG_TYPE", 66);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_LOCKED_SECMEM", 67);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DISABLE_PRIV_DROP", 68);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_CCM_LENGTHS", 69);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_CLOSE_RANDOM_DEVICE", 70);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_INACTIVATE_FIPS_FLAG", 71);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_REACTIVATE_FIPS_FLAG", 72);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_SBOX", 73);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_DRBG_REINIT", 74);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_TAGLEN", 75);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_GET_TAGLEN", 76);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_REINIT_SYSCALL_CLAMP", 77);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_AUTO_EXPAND_SECMEM", 78);
    WSLUA_REG_GLOBAL_INTEGER(L, "GCRYCTL_SET_ALLOW_WEAK_KEY", 79);
    WSLUA_REGISTER_CLASS(GcryptCipher);
    return 0;
}

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
