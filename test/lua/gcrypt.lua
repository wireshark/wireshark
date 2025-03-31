-- This is a test script for tshark/wireshark.
-- This script runs inside tshark/wireshark, so to run it do:
-- wireshark -X lua_script:<path_to_testdir>/lua/gcrypt.lua
-- tshark -r bogus.cap -X lua_script:<path_to_testdir>/lua/gcrypt.lua

-- Tests Gcrypt class and functions

local testlib = require("testlib")

-- Symmetric Cipher
-- GcryptCipher Class
local OPEN = "open"
local CTL = "ctl"
local INFO = "info"
local ENCRYPT = "encrypt"
local DECRYPT = "decrypt"
local SETKEY = "setkey"
local SETIV = "setiv"
local AUTHENTICATE = "authenticate"
local GETTAG = "gettag"
local CHECKTAG = "checktag"
local SETCTR = "setctr"
-- functions
local ALGO_INFO = "algo_info"
local ALGO_NAME = "algo_name"
local MAP_NAME = "map_name"
local MODE_FROM_OID = "mode_from_oid"
local GET_ALGO_KEYLEN = "get_algo_keylen"
local GET_ALGO_BLKLEN = "get_algo_blklen"

-- expected number of runs per type
local taptests = {
-- Symmetric Cipher
    [OPEN] = 5,
    [CTL] = 5,
    [INFO] = 3,
    [ENCRYPT] = 4,
    [DECRYPT] = 4,
    [SETKEY] = 3,
    [SETIV] = 3,
    [AUTHENTICATE] = 2,
    [GETTAG] = 1,
    [CHECKTAG] = 2,
    [SETCTR] = 4,
    [ALGO_INFO] = 6,
    [ALGO_NAME] = 2,
    [MAP_NAME] = 2,
    [MODE_FROM_OID] = 3,
    [GET_ALGO_KEYLEN] = 3,
    [GET_ALGO_BLKLEN] = 3
}

local gcrypt_cbc = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
local gcrypt_gcm = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)
local plain_data

testlib.init(taptests)

-- the following are so we can use pcall (which needs a function to call)

-- Symmetric Cipher

local function GcryptCipher_open(gcrypt, algorithm, mode, flags)
    local value = GcryptCipher.open(algorithm, mode, flags)
end

local function GcryptCipher_ctl(gcrypt, cmd, buffer)
    gcrypt:ctl(cmd, buffer)
end

local function GcryptCipher_info(gcrypt, what, buffer_size, nbytes)
    local userdata, nbytes = gcrypt:info(what, buffer_size, nbytes)
end

local function GcryptCipher_encrypt(gcrypt, data_out, data_in)
    gcrypt:ctl(GCRYCTL_RESET, ByteArray.new())
    gcrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    gcrypt:encrypt(data_out, data_in)
end

local function GcryptCipher_decrypt(gcrypt, data_out, data_in)
    gcrypt:ctl(GCRYCTL_RESET, ByteArray.new())
    gcrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    gcrypt:decrypt(data_out, data_in)
end

local function GcryptCipher_setkey(gcrypt, key)
    gcrypt:setkey(key)
end

local function GcryptCipher_setiv(gcrypt, iv)
    gcrypt:setiv(iv)
end

local function GcryptCipher_authenticate(gcrypt, data)
    gcrypt:ctl(GCRYCTL_RESET, ByteArray.new())
    gcrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    gcrypt:setiv(ByteArray.new("01020304050607080102030405060708"))
    gcrypt:authenticate(data)
end

local function GcryptCipher_gettag(gcrypt)
    gcrypt:ctl(GCRYCTL_RESET, ByteArray.new())
    gcrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    gcrypt:setiv(ByteArray.new("01020304050607080102030405060708"))
    gcrypt:authenticate(ByteArray.new("55667788"))
    gcrypt:encrypt(ByteArray.new("000102030405060708090a0b0c0d0e0f"), NULL)
    return gcrypt:gettag()
end

local function GcryptCipher_checktag(gcrypt, tag)
    gcrypt:ctl(GCRYCTL_RESET, ByteArray.new())
    gcrypt:setkey(ByteArray.new("abcdefabcdef1234abcdefabcdef1234"))
    gcrypt:setiv(ByteArray.new("01020304050607080102030405060708"))
    gcrypt:authenticate(ByteArray.new("55667788"))
    gcrypt:decrypt(NULL, ByteArray.new("14E50ECE75184B758A9DF304F3918A64"))
    return gcrypt:checktag(tag)
end

local function GcryptCipher_setctr(gcrypt, ctr, ctr_len)
    gcrypt:setctr(ctr, ctr_len)
end

------------- test script ------------

-- Symmetric Cipher

testlib.testing(OPEN, "negative tests")
testlib.test(OPEN,"GcryptCipher:open-0", not pcall(GcryptCipher_open))
testlib.test(OPEN,"GcryptCipher:open-1", not pcall(GcryptCipher_open, 0xFFFF, GCRY_CIPHER_MODE_CBC, 0))
testlib.test(OPEN,"GcryptCipher:open-2", not pcall(GcryptCipher_open, GCRY_CIPHER_AES, 0xFFFF, 0))
testlib.test(OPEN,"GcryptCipher:open-3", not pcall(GcryptCipher_open, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, ""))

testlib.testing(OPEN, "positive tests")
testlib.test(OPEN,"GcryptCipher:open-4", GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0))

testlib.testing(CTL, "negative tests")
testlib.test(CTL,"GcryptCipher:ctl-0", not pcall(GcryptCipher_ctl))
testlib.test(CTL,"GcryptCipher:ctl-1", not pcall(GcryptCipher_ctl, gcrypt_cbc, 0xffff, ByteArray.new()))
testlib.test(CTL,"GcryptCipher:ctl-2", not pcall(GcryptCipher_ctl, gcrypt_cbc, GCRYCTL_CFB_SYNC, 0))

testlib.testing(CTL, "positive tests")
testlib.test(CTL,"GcryptCipher:ctl-3", pcall(GcryptCipher_ctl, gcrypt_cbc, GCRYCTL_CFB_SYNC, ByteArray.new()))
testlib.test(CTL,"GcryptCipher:ctl-4", pcall(GcryptCipher_ctl, gcrypt_cbc, GCRYCTL_SET_CBC_MAC, ByteArray.new()))

testlib.testing(INFO, "negative tests")
testlib.test(INFO,"GcryptCipher:info-0", not pcall(GcryptCipher_info, gcrypt_gcm, 0xffff, NULL, 1))
testlib.test(INFO,"GcryptCipher:info-1", not pcall(GcryptCipher_info, gcrypt_gcm, GCRYCTL_GET_TAGLEN, ByteArray.new(), NULL))

testlib.testing(INFO, "positive tests")
testlib.test(INFO,"GcryptCipher:info-2", pcall(GcryptCipher_info, gcrypt_gcm, GCRYCTL_GET_TAGLEN, NULL, 1))

testlib.testing(ENCRYPT, "negative tests")
testlib.test(ENCRYPT,"GcryptCipher:encrypt-0", not pcall(GcryptCipher_encrypt, gcrypt_cbc))

testlib.testing(ENCRYPT, "positive tests")
testlib.test(ENCRYPT,"GcryptCipher:encrypt-1", gcrypt_cbc:encrypt(NULL, ByteArray.new("000102030405060708090A0B0C0D0E0F")):tohex() == "E27FC30A38E17B6BB7E67AFF2800792F")
plain_data = ByteArray.new("000102030405060708090A0B0C0D0E0F")
testlib.test(ENCRYPT,"GcryptCipher:encrypt-2", pcall(GcryptCipher_encrypt, gcrypt_cbc, plain_data, NULL))
testlib.test(ENCRYPT,"GcryptCipher:encrypt-3", plain_data:tohex() == "E27FC30A38E17B6BB7E67AFF2800792F")

testlib.testing(DECRYPT, "negative tests")
testlib.test(DECRYPT,"GcryptCipher:decrypt-0", not pcall(GcryptCipher_decrypt, gcrypt_cbc))

testlib.testing(DECRYPT, "positive tests")
testlib.test(DECRYPT,"GcryptCipher:decrypt-1", gcrypt_cbc:decrypt(NULL, ByteArray.new("E27FC30A38E17B6BB7E67AFF2800792F")):tohex() == "000102030405060708090A0B0C0D0E0F")
plain_data = ByteArray.new("E27FC30A38E17B6BB7E67AFF2800792F")
testlib.test(DECRYPT,"GcryptCipher:decrypt-2", pcall(GcryptCipher_decrypt, gcrypt_cbc, plain_data, NULL))
testlib.test(DECRYPT,"GcryptCipher:decrypt-3", plain_data:tohex() == "000102030405060708090A0B0C0D0E0F")

testlib.testing(SETKEY, "negative tests")
testlib.test(SETKEY,"GcryptCipher:setkey-0", not pcall(GcryptCipher_setkey, gcrypt_cbc))
testlib.test(SETKEY,"GcryptCipher:setkey-1", not pcall(GcryptCipher_setkey, gcrypt_cbc, ByteArray.new("abcdefabcdef1234abcdefabcdef12")))

testlib.testing(SETKEY, "positive tests")
testlib.test(SETKEY,"GcryptCipher:setkey-2", pcall(GcryptCipher_setkey, gcrypt_cbc, ByteArray.new("abcdefabcdef1234abcdefabcdef1234")))

testlib.testing(SETIV, "negative tests")
testlib.test(SETIV,"GcryptCipher:setiv-0", not pcall(GcryptCipher_setiv, gcrypt_cbc))
testlib.test(SETIV,"GcryptCipher:setiv-1", not pcall(GcryptCipher_setiv, gcrypt_cbc, NULL))

testlib.testing(SETIV, "positive tests")
testlib.test(SETIV,"GcryptCipher:setiv-2", pcall(GcryptCipher_setiv, gcrypt_cbc, ByteArray.new("abcdefabcdef1234abcdefabcdef1234")))

testlib.testing(AUTHENTICATE, "negative tests")
testlib.test(AUTHENTICATE,"GcryptCipher:authenticate-0", not pcall(GcryptCipher_authenticate, gcrypt_gcm))

testlib.testing(AUTHENTICATE, "positive tests")
testlib.test(AUTHENTICATE,"GcryptCipher:authenticate-1", pcall(GcryptCipher_authenticate, gcrypt_gcm, ByteArray.new("55667788")))

testlib.testing(GETTAG, "positive tests")
print(gcrypt_gcm:gettag():tohex())
testlib.test(GETTAG,"GcryptCipher:gettag-0", GcryptCipher_gettag(gcrypt_gcm):tohex() == "08805135EBBDFE49BFBBB82007F88AB3")

testlib.testing(CHECKTAG, "negative tests")
testlib.test(CHECKTAG,"GcryptCipher:checktag-0", GcryptCipher_checktag(gcrypt_gcm, ByteArray.new("00805135EBBDFE49BFBBB82007F88A00")) ~= 0)

testlib.testing(CHECKTAG, "positive tests")
testlib.test(CHECKTAG,"GcryptCipher:checktag-1", GcryptCipher_checktag(gcrypt_gcm, ByteArray.new("08805135EBBDFE49BFBBB82007F88AB3")))

testlib.testing(SETCTR, "positive tests")
testlib.test(SETCTR,"GcryptCipher:setctr-0", pcall(GcryptCipher_setctr, gcrypt_cbc, NULL, NULL))
testlib.test(SETCTR,"GcryptCipher:setctr-1", pcall(GcryptCipher_setctr, gcrypt_cbc, NULL, 0))
testlib.test(SETCTR,"GcryptCipher:setctr-2", pcall(GcryptCipher_setctr, gcrypt_cbc, ByteArray.new("000102030405060708090A0B0C0D0E0F"), 0))
testlib.test(SETCTR,"GcryptCipher:setctr-3", pcall(GcryptCipher_setctr, gcrypt_cbc, ByteArray.new("000102030405060708090A0B0C0D0E0F"), 16))

testlib.testing(ALGO_INFO, "negative tests")
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-0", not pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_GET_KEYLEN, NULL, NULL))
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-1", not pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_GET_KEYLEN, ByteArray.new(), NULL))
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-2", not pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_GET_BLKLEN, NULL, NULL))

testlib.testing(ALGO_INFO, "positive tests")
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-3", pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_GET_KEYLEN, NULL, 0))
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-4", pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_GET_BLKLEN, NULL, 0))
testlib.test(ALGO_INFO,"gcry_cipher_algo_info-5", pcall(gcry_cipher_algo_info, GCRY_CIPHER_AES, GCRYCTL_TEST_ALGO, NULL, NULL))

testlib.testing(ALGO_NAME, "positive tests")
testlib.test(ALGO_NAME,"gcry_cipher_algo_name-0", gcry_cipher_algo_name(0xFFFF) == "?")
testlib.test(ALGO_NAME,"gcry_cipher_algo_name-1", gcry_cipher_algo_name(GCRY_CIPHER_AES) == "AES" )

testlib.testing(MAP_NAME, "positive tests")
testlib.test(MAP_NAME,"gcry_cipher_map_name-0", gcry_cipher_map_name(0xFFFF) == 0)
testlib.test(MAP_NAME,"gcry_cipher_map_name-1", pcall(gcry_cipher_map_name, "AES"))

testlib.testing(MODE_FROM_OID, "negative tests")
testlib.test(MODE_FROM_OID,"gcry_cipher_mode_from_oid-0", not pcall(gcry_cipher_mode_from_oid))

testlib.testing(MODE_FROM_OID, "positive tests")
testlib.test(MODE_FROM_OID,"gcry_cipher_mode_from_oid-1", gcry_cipher_mode_from_oid("2.16.840.1.101.3.4.1.2") == GCRY_CIPHER_MODE_CBC)
testlib.test(MODE_FROM_OID,"gcry_cipher_mode_from_oid-2", gcry_cipher_mode_from_oid("NONE") == 0)

testlib.testing(GET_ALGO_KEYLEN, "negative tests")
testlib.test(GET_ALGO_KEYLEN,"gcry_cipher_get_algo_keylen-0", not pcall(gcry_cipher_get_algo_keylen))

testlib.testing(GET_ALGO_KEYLEN, "positive tests")
testlib.test(GET_ALGO_KEYLEN,"gcry_cipher_get_algo_keylen-1", gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES) == 16)
testlib.test(GET_ALGO_KEYLEN,"gcry_cipher_get_algo_keylen-2", gcry_cipher_get_algo_keylen(0xFFFF) == 0)

testlib.testing(GET_ALGO_BLKLEN, "negative tests")
testlib.test(GET_ALGO_BLKLEN,"gcry_cipher_get_algo_blklen-0", not pcall(gcry_cipher_get_algo_blklen))

testlib.testing(GET_ALGO_BLKLEN, "positive tests")
testlib.test(GET_ALGO_BLKLEN,"gcry_cipher_get_algo_blklen-1", gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES) == 16)
testlib.test(GET_ALGO_BLKLEN,"gcry_cipher_get_algo_keylen-2", gcry_cipher_get_algo_blklen(0xFFFF) == 0)

testlib.getResults()
