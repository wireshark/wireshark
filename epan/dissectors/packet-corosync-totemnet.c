/* packet-corosync-totemnet.c
 * Dissector routines for the lowest level(encryption/decryption) protocol used in Corosync cluster engine
 * Copyright 2009 2010 2014 Masatake YAMATO <yamato@redhat.com>
 * Copyright (c) 2010 2014 Red Hat, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/sha1.h>
#include <wsutil/sober128.h>

static dissector_handle_t corosync_totemsrp_handle;

/* This dissector deals packets defined in totemnet.c of corosync
   cluster engine. In the totemnet.c the packet is encrypted and decrypted
   with LibTomCrypt. This dissector tries decrypting the packet with
   sober128 and sha1 functions in wireshark. */

/*
 * Dissector body
 */

#define PORT_COROSYNC_TOTEMNET 5405

/* Forward declaration we need below */
void proto_register_corosync_totemnet(void);
void proto_reg_handoff_corosync_totemnet(void);

/* Initialize the protocol and registered fields */
static int proto_corosync_totemnet = -1;

/* field of struct security_header */
static int hf_corosync_totemnet_security_header_hash_digest    = -1;
static int hf_corosync_totemnet_security_header_salt           = -1;
static int hf_corosync_totemnet_security_crypto_type           = -1;
static int hf_corosync_totemnet_security_crypto_key            = -1;

/* configurable parameters */
static guint   corosync_totemnet_port              = PORT_COROSYNC_TOTEMNET;
static gchar*  corosync_totemnet_private_keys      = NULL;
static gchar** corosync_totemnet_private_keys_list = NULL;

/* Initialize the subtree pointers */
static gint ett_corosync_totemnet_security_header              = -1;


#define SALT_SIZE      16

#define TOTEM_CRYPTO_SOBER 0
#define TOTEM_CRYPTO_NSS   1

static const value_string corosync_totemnet_crypto_type[] = {
  { TOTEM_CRYPTO_SOBER, "SOBER" },
  { TOTEM_CRYPTO_NSS,   "NSS"   },
  { 0, NULL }
};


static int
dissect_corosync_totemnet_security_header(tvbuff_t *tvb,
                                          packet_info *pinfo, proto_tree *parent_tree,
                                          gboolean check_crypt_type,
                                          const gchar* key)
{
  proto_item *item;
  proto_tree *tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "COROSYNC/TOTEMNET");
  col_clear(pinfo->cinfo, COL_INFO);

  if (parent_tree)
    {
      item = proto_tree_add_item(parent_tree, proto_corosync_totemnet, tvb, 0,
                                 -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_corosync_totemnet_security_header);

      proto_tree_add_item(tree,
                          hf_corosync_totemnet_security_header_hash_digest,
                          tvb, 0, SHA1_DIGEST_LEN, ENC_NA);
      proto_tree_add_item(tree,
                          hf_corosync_totemnet_security_header_salt,
                          tvb, SHA1_DIGEST_LEN, SALT_SIZE, ENC_NA);

      if (check_crypt_type)
        {
          int io_len = tvb_reported_length(tvb);
          proto_item * key_item;

          proto_tree_add_item(tree,
                              hf_corosync_totemnet_security_crypto_type,
                              tvb, io_len - 1, 1, ENC_BIG_ENDIAN);
          key_item = proto_tree_add_string(tree,
                                           hf_corosync_totemnet_security_crypto_key,
                                           tvb, 0, 0, key);
          PROTO_ITEM_SET_GENERATED(key_item);
        }
    }
  return SHA1_DIGEST_LEN + SALT_SIZE;
}

/* About totemnet.c of corosync cluster engine:
 *
 * dissect_corosynec_totemnet_with_decryption() is derived from
 * totemnet.c in corosync which is licensed under 3-clause BSD license.
 * However, to merge this dissector to wireshark official source tree,
 * corosync developers permit EXPLICITLY to reuse totemnet.c in GPL.
 *
 http://permalink.gmane.org/gmane.linux.redhat.cluster/19087
 ------------------------------------------------------------
  Steven Dake | 4 Jan 2011 22:02
  Re: [Openais] packet dissectors for totempg, cman, clvmd, rgmanager, cpg,

On 12/14/2010 08:04 AM, Masatake YAMATO wrote:
> Thank you for replying.
>
>> Masatake,
>>
>> Masatake YAMATO napsal(a):
>>> I'd like to your advice more detail seriously.
>>> I've been developing this code for three years.
>>> I don't want to make this code garbage.
>>>
>>>> Masatake,
>>>> I'm pretty sure that biggest problem of your code was that it was
>>>> licensed under BSD (three clause, same as Corosync has)
>>>> license. Wireshark is licensed under GPL and even I like BSD licenses
>>>> much more, I would recommend you to try to relicense code under GPL
>>>> and send them this code.
>>>>
>>>> Regards,
>>>>   Honza
>>> I got the similar comment from wireshark developer.
>>> Please, read the discussion:
>>>     https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3232
>>>
>>
>> I've read that thread long time before I've sent previous mail, so
>> thats reason why I think that Wireshark developers just feel MUCH more
>> comfortable with GPL and thats reason why they just ignoring it.
>
> I see.
>
>>> In my understanding there is no legal problem in putting 3-clause BSD
>>> code into GPL code.  Acutally wireshark includes some 3-clause BSD
>>> code:
>>>
nnn>>
>> Actually there is really not. BSD to GPL works without problem, but
>> many people just don't know it...
>
> ...it is too bad. I strongly believe FOSS developers should know the
> intent behind of the both licenses.
>
>>> epan/dissectors/packet-radiotap-defs.h:
>>> *//*-
>>>  * Copyright (c) 2003, 2004 David Young.  All rights reserved.
>>>  *
...
>>>  *
>>>  * Redistribution and use in source and binary forms, with or without
>>>  * modification, are permitted provided that the following conditions
>>>  * are met:
>>>  * 1. Redistributions of source code must retain the above copyright
>>>  *    notice, this list of conditions and the following disclaimer.
>>>  * 2. Redistributions in binary form must reproduce the above copyright
>>>  *    notice, this list of conditions and the following disclaimer in the
>>>  *    documentation and/or other materials provided with the distribution.
>>>  * 3. The name of David Young may not be used to endorse or promote
>>>  *    products derived from this software without specific prior
>>>  *    written permission.
>>>  *
>>>  * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
>>>  * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
>>>  * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
>>>  * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
>>>  * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
>>>  * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
>>>  * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
>>>  * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
>>>  * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
>>>  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
>>>  * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
>>>  * OF SUCH DAMAGE.
>>>  *//*
>>> I'd like to separate the legal issue and preference. I think I
>>> understand the importance of preference of upstream
>>> developers. However, I'd like to clear the legal issue first.
>>>
>>
>> Legally it's ok. But as you said, developers preference are
>> different. And because you are trying to change THEIR code it's
>> sometimes better to play they rules.
>
> I see.
>
>>> I can image there are people who prefer to GPL as the license covering
>>> their software. But here I've taken some corosync code in my
>>> dissector. It is essential part of my dissector. And corosync is
>>
>> ^^^ This may be problem. Question is how big is that part and if it
>> can be possible to make exception there. Can you point that code?
>>
>> Steve, we were able to relicense HUGE portion of code in case of
>> libqb, are we able to make the same for Wireshark dissector?
>
> Could you see https://github.com/masatake/wireshark-plugin-rhcs/blob/master/src/packet-corosync-totemnet.c#L156
> I refer totemnet.c to write dissect_corosynec_totemnet_with_decryption() function.
>
>>> licensed in 3-clause BSD, as you know. I'd like to change the license
>>> to merge my code to upstream project. I cannot do it in this context.
>>> See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3232#c13
>>> Thank you.
>>
>> Regards,
>>   Honza
>
> Masatake YAMATO

Masatake,

Red Hat is the author of the totemnet file and can provide that code
under GPL if you like.  We cannot modify the license for libtomcrypt as
we are not the authors.  Feel free to change the license for that
particular code you rewrote in the link

> Could you see
https://github.com/masatake/wireshark-plugin-rhcs/blob/master/src/packet-corosync-totemnet.c#L156

under a GPL license if it helps move things along.

Regards
-steveu
       */

static int
dissect_corosynec_totemnet_with_decryption(tvbuff_t *tvb,
                                           packet_info *pinfo, proto_tree *parent_tree,
                                           gboolean check_crypt_type,
                                           const gchar* key_for_trial)
{
  unsigned char  keys[48];
  sober128_prng     keygen_prng_state;
  sober128_prng     stream_prng_state;
  unsigned char *hmac_key       = &keys[32];
  unsigned char *cipher_key     = &keys[16];
  unsigned char *initial_vector = &keys[0];
  unsigned char  digest_comparison[SHA1_DIGEST_LEN];

  int            io_len;
  guint8        *io_base;

#define PRIVATE_KEY_LEN_MAX 256
  gchar          private_key[PRIVATE_KEY_LEN_MAX];
  gsize          private_key_len;
  unsigned char* hash_digest;
  unsigned char* salt;

  io_len = tvb_reported_length(tvb) - (check_crypt_type? 1: 0);
  if (io_len < SHA1_DIGEST_LEN + SALT_SIZE) {
    return 0;
  }

  io_base = (guint8 *)tvb_memdup(pinfo->pool, tvb, 0, io_len + (check_crypt_type? 1: 0));
  if (check_crypt_type &&
      ( io_base[io_len] != TOTEM_CRYPTO_SOBER )) {
    return 0;
  }

  hash_digest = io_base;
  salt        = io_base + SHA1_DIGEST_LEN;


  memset(private_key, 0, sizeof(private_key));

  private_key_len = (strlen(key_for_trial)+4) & 0xFC;
  if (private_key_len > PRIVATE_KEY_LEN_MAX)
    private_key_len = PRIVATE_KEY_LEN_MAX;
  g_strlcpy(private_key, key_for_trial, private_key_len);

  /*
   * Generate MAC, CIPHER, IV keys from private key
   */
  memset (keys, 0, sizeof(keys));
  sober128_start (&keygen_prng_state);
  sober128_add_entropy(private_key,
                                  (unsigned long)private_key_len, &keygen_prng_state);
  sober128_add_entropy (salt, SALT_SIZE, &keygen_prng_state);
  sober128_read (keys, sizeof (keys), &keygen_prng_state);

  /*
   * Setup stream cipher
   */
  sober128_start (&stream_prng_state);
  sober128_add_entropy (cipher_key, 16, &stream_prng_state);
  sober128_add_entropy (initial_vector, 16, &stream_prng_state);

  /*
   * Authenticate contents of message
   */
  sha1_hmac(hmac_key, 16,
            io_base + SHA1_DIGEST_LEN, io_len - SHA1_DIGEST_LEN,
            digest_comparison);

  if (memcmp (digest_comparison, hash_digest, SHA1_DIGEST_LEN) != 0)
      return 0;

  /*
   * Decrypt the contents of the message with the cipher key
   */

  sober128_read (io_base + SHA1_DIGEST_LEN + SALT_SIZE,
                            io_len - (SHA1_DIGEST_LEN + SALT_SIZE),
                            &stream_prng_state);


  /*
   * Dissect the decrypted data
   */
  {
    tvbuff_t *decrypted_tvb;
    tvbuff_t *next_tvb;


    decrypted_tvb = tvb_new_real_data(io_base, io_len, io_len);

    tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");


    dissect_corosync_totemnet_security_header(decrypted_tvb, pinfo, parent_tree,
                                              check_crypt_type, key_for_trial);

    next_tvb = tvb_new_subset(decrypted_tvb,
                              SHA1_DIGEST_LEN + SALT_SIZE,
                              io_len - (SHA1_DIGEST_LEN + SALT_SIZE),
                              io_len - (SHA1_DIGEST_LEN + SALT_SIZE));

    return call_dissector(corosync_totemsrp_handle, next_tvb, pinfo, parent_tree) + SHA1_DIGEST_LEN + SALT_SIZE;
  }
}

static int
dissect_corosynec_totemnet(tvbuff_t *tvb,
                           packet_info *pinfo, proto_tree *parent_tree,
                           void *data _U_)
{
  if (corosync_totemnet_private_keys_list)
    {
      static int last_key_index = -1;
      int key_index;

      static int last_check_crypt_type_index;
      int check_crypt_type_index = -1;
      gboolean check_crypt_type_list[] = {FALSE, TRUE};


      if (last_key_index != -1)
        {
          int r;

          r = dissect_corosynec_totemnet_with_decryption(tvb,
                                                         pinfo,
                                                         parent_tree,
                                                         check_crypt_type_list[last_check_crypt_type_index],
                                                         corosync_totemnet_private_keys_list[last_key_index]);
          if (r > 0)
            return r;
          else
            last_key_index = -1;
        }

      for (key_index = 0;
           corosync_totemnet_private_keys_list[key_index];
           key_index++)
        {
          for (check_crypt_type_index = 0;
               check_crypt_type_index < 2;
               check_crypt_type_index++)
            {
              int r;

              r = dissect_corosynec_totemnet_with_decryption(tvb,
                                                             pinfo,
                                                             parent_tree,
                                                             check_crypt_type_list[check_crypt_type_index],
                                                             corosync_totemnet_private_keys_list[key_index]);
              if (r > 0)
                {
                  last_key_index = key_index;
                  last_check_crypt_type_index = check_crypt_type_index;
                  return r;
                }
              else if (r < 0)
                break;

            }
        }
    }

  /* Not encrypted */
  return call_dissector(corosync_totemsrp_handle, tvb, pinfo, parent_tree);
}


void
proto_register_corosync_totemnet(void)
{
  module_t *corosync_totemnet_module;

  static hf_register_info hf[] = {
    { &hf_corosync_totemnet_security_header_hash_digest,
      { "Hash digest", "corosync_totemnet.security_header_hash_digest",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemnet_security_header_salt,
      { "Salt", "corosync_totemnet.security_header_salt",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemnet_security_crypto_type,
      { "Cryptographic Type", "corosync_totemnet.security_crypto_type",
        FT_UINT8, BASE_DEC, VALS(corosync_totemnet_crypto_type), 0x0,
        NULL, HFILL }},
    { &hf_corosync_totemnet_security_crypto_key,
      { "Private Key for decryption", "corosync_totemnet.security_crypto_key",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
  };

  static gint *ett_corosync_totemnet[] = {
    &ett_corosync_totemnet_security_header,
  };

  proto_corosync_totemnet = proto_register_protocol("Totemnet Layer of Corosync Cluster Engine",
                                                    "COROSYNC/TOTEMNET", "corosync_totemnet");
  proto_register_field_array(proto_corosync_totemnet, hf, array_length(hf));
  proto_register_subtree_array(ett_corosync_totemnet, array_length(ett_corosync_totemnet));

  corosync_totemnet_module = prefs_register_protocol(proto_corosync_totemnet,
                                                     proto_reg_handoff_corosync_totemnet);

  prefs_register_uint_preference(corosync_totemnet_module, "udp.port",
                                 "UDP Port",
                                 "Set the UDP port for totem ring protocol implemented in corosync cluster engine",
                                 10,
                                 &corosync_totemnet_port);
  prefs_register_string_preference(corosync_totemnet_module, "private_keys", "Private keys",
                                   "Semicolon-separated  list of keys for decryption(e.g. key1;key2;..." ,
                                   (const gchar **)&corosync_totemnet_private_keys);
}

void
proto_reg_handoff_corosync_totemnet(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t corosync_totemnet_handle;
  static int port = 0;


  if (initialized)
    {
      dissector_delete_uint("udp.port", port, corosync_totemnet_handle);
      dissector_delete_uint("udp.port", port - 1, corosync_totemnet_handle);
    }
  else
    {
      corosync_totemnet_handle = create_dissector_handle(dissect_corosynec_totemnet,
                                                             proto_corosync_totemnet);
      corosync_totemsrp_handle = find_dissector_add_dependency("corosync_totemsrp", proto_corosync_totemnet);

      initialized = TRUE;
    }

  if (corosync_totemnet_private_keys_list) {
    g_strfreev(corosync_totemnet_private_keys_list);
    corosync_totemnet_private_keys_list = NULL;
  }
  corosync_totemnet_private_keys_list = g_strsplit(corosync_totemnet_private_keys,
                                                   ";",
                                                   0);
  port  = corosync_totemnet_port;
  dissector_add_uint("udp.port", port,     corosync_totemnet_handle);
  dissector_add_uint("udp.port", port - 1, corosync_totemnet_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
