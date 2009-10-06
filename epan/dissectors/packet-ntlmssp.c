/* packet-ntlmssp.c
 * Add-on for better NTLM v1/v2 handling 
 * Copyright 2009 Matthieu Patou <matthieu.patou@matws.net>
 * Routines for NTLM Secure Service Provider
 * Devin Heitmueller <dheitmueller@netilla.com>
 * Copyright 2003, Tim Potter <tpot@samba.org>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#ifdef DEBUG_NTLMSSP
#include <stdio.h>
#endif
#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>

#include "packet-windows-common.h"
#include "packet-smb-common.h"
#include "packet-frame.h"
#include <epan/asn1.h>
#include "packet-kerberos.h"
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include <epan/crypt/crypt-rc4.h>
#include <epan/crypt/crypt-md4.h>
#include <epan/crypt/crypt-md5.h>
#include <epan/crypt/crypt-des.h>
#include "packet-dcerpc.h"
#include "packet-gssapi.h"
#include <epan/crc32.h>

#include "packet-ntlmssp.h"

static int ntlmssp_tap = -1;

/* Message types */

#define NTLMSSP_NEGOTIATE 1
#define NTLMSSP_CHALLENGE 2
#define NTLMSSP_AUTH      3
#define NTLMSSP_UNKNOWN   4
#define CLIENT_SIGN_TEXT "session key to client-to-server signing key magic constant"
#define CLIENT_SEAL_TEXT "session key to client-to-server sealing key magic constant"
#define SERVER_SIGN_TEXT "session key to server-to-client signing key magic constant"
#define SERVER_SEAL_TEXT "session key to server-to-client sealing key magic constant"

static const value_string ntlmssp_message_types[] = {
  { NTLMSSP_NEGOTIATE, "NTLMSSP_NEGOTIATE" },
  { NTLMSSP_CHALLENGE, "NTLMSSP_CHALLENGE" },
  { NTLMSSP_AUTH, "NTLMSSP_AUTH" },
  { NTLMSSP_UNKNOWN, "NTLMSSP_UNKNOWN" },
  { 0, NULL }
};

typedef struct _md4_pass {
  guint8 md4[16];
} md4_pass;

static unsigned char zeros[24] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
static GHashTable* hash_packet = NULL;

/*
 * NTLMSSP negotiation flags
 * Taken from Samba
 *
 * See also
 *
 *	http://davenport.sourceforge.net/ntlm.html
 *
 * although that document says that:
 *
 *	0x00010000 is "Target Type Domain";
 *	0x00020000 is "Target Type Server"
 *	0x00040000 is "Target Type Share";
 *
 * and that 0x00100000, 0x00200000, and 0x00400000 are
 * "Request Init Response", "Request Accept Response", and
 * "Request Non-NT Session Key", rather than those values shifted
 * right one having those interpretations.
 *
 * UPDATE: Further information obtained from [MS-NLMP]: 
 * NT LAN Manager (NTLM) Authentication Protocol Specification
 * http://msdn2.microsoft.com/en-us/library/cc236621.aspx
 *
 */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_00000008         0x00000008
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_DATAGRAM         0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_00000100         0x00000100
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_NT_ONLY          0x00000400
#define NTLMSSP_NEGOTIATE_00000800         0x00000800
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED 0x00001000
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED 0x00002000
#define NTLMSSP_NEGOTIATE_00004000         0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN         0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER         0x00020000
#define NTLMSSP_TARGET_TYPE_SHARE          0x00040000
#define NTLMSSP_NEGOTIATE_EXTENDED_SECURITY 0x00080000
#define NTLMSSP_NEGOTIATE_IDENTIFY         0x00100000
#define NTLMSSP_NEGOTIATE_00200000         0x00200000
#define NTLMSSP_REQUEST_NON_NT_SESSION     0x00400000
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000
#define NTLMSSP_NEGOTIATE_01000000         0x01000000
#define NTLMSSP_NEGOTIATE_VERSION          0x02000000
#define NTLMSSP_NEGOTIATE_04000000         0x04000000
#define NTLMSSP_NEGOTIATE_08000000         0x08000000
#define NTLMSSP_NEGOTIATE_10000000         0x10000000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000
#define NTLMSSP_NEGOTIATE_56               0x80000000

static int proto_ntlmssp = -1;
static int hf_ntlmssp = -1;
static int hf_ntlmssp_auth = -1;
static int hf_ntlmssp_message_type = -1;
static int hf_ntlmssp_negotiate_flags = -1;
static int hf_ntlmssp_negotiate_flags_01 = -1;
static int hf_ntlmssp_negotiate_flags_02 = -1;
static int hf_ntlmssp_negotiate_flags_04 = -1;
static int hf_ntlmssp_negotiate_flags_08 = -1;
static int hf_ntlmssp_negotiate_flags_10 = -1;
static int hf_ntlmssp_negotiate_flags_20 = -1;
static int hf_ntlmssp_negotiate_flags_40 = -1;
static int hf_ntlmssp_negotiate_flags_80 = -1;
static int hf_ntlmssp_negotiate_flags_100 = -1;
static int hf_ntlmssp_negotiate_flags_200 = -1;
static int hf_ntlmssp_negotiate_flags_400 = -1;
static int hf_ntlmssp_negotiate_flags_800 = -1;
static int hf_ntlmssp_negotiate_flags_1000 = -1;
static int hf_ntlmssp_negotiate_flags_2000 = -1;
static int hf_ntlmssp_negotiate_flags_4000 = -1;
static int hf_ntlmssp_negotiate_flags_8000 = -1;
static int hf_ntlmssp_negotiate_flags_10000 = -1;
static int hf_ntlmssp_negotiate_flags_20000 = -1;
static int hf_ntlmssp_negotiate_flags_40000 = -1;
static int hf_ntlmssp_negotiate_flags_80000 = -1;
static int hf_ntlmssp_negotiate_flags_100000 = -1;
static int hf_ntlmssp_negotiate_flags_200000 = -1;
static int hf_ntlmssp_negotiate_flags_400000 = -1;
static int hf_ntlmssp_negotiate_flags_800000 = -1;
static int hf_ntlmssp_negotiate_flags_1000000 = -1;
static int hf_ntlmssp_negotiate_flags_2000000 = -1;
static int hf_ntlmssp_negotiate_flags_4000000 = -1;
static int hf_ntlmssp_negotiate_flags_8000000 = -1;
static int hf_ntlmssp_negotiate_flags_10000000 = -1;
static int hf_ntlmssp_negotiate_flags_20000000 = -1;
static int hf_ntlmssp_negotiate_flags_40000000 = -1;
static int hf_ntlmssp_negotiate_flags_80000000 = -1;
static int hf_ntlmssp_negotiate_workstation_strlen = -1;
static int hf_ntlmssp_negotiate_workstation_maxlen = -1;
static int hf_ntlmssp_negotiate_workstation_buffer = -1;
static int hf_ntlmssp_negotiate_workstation = -1;
static int hf_ntlmssp_negotiate_domain_strlen = -1;
static int hf_ntlmssp_negotiate_domain_maxlen = -1;
static int hf_ntlmssp_negotiate_domain_buffer = -1;
static int hf_ntlmssp_negotiate_domain = -1;
static int hf_ntlmssp_ntlm_server_challenge = -1;
static int hf_ntlmssp_ntlm_client_challenge = -1;
static int hf_ntlmssp_reserved = -1;
static int hf_ntlmssp_challenge_domain = -1;
static int hf_ntlmssp_auth_username = -1;
static int hf_ntlmssp_auth_domain = -1;
static int hf_ntlmssp_auth_hostname = -1;
static int hf_ntlmssp_auth_lmresponse = -1;
static int hf_ntlmssp_auth_ntresponse = -1;
static int hf_ntlmssp_auth_sesskey = -1;
static int hf_ntlmssp_string_len = -1;
static int hf_ntlmssp_string_maxlen = -1;
static int hf_ntlmssp_string_offset = -1;
static int hf_ntlmssp_blob_len = -1;
static int hf_ntlmssp_blob_maxlen = -1;
static int hf_ntlmssp_blob_offset = -1;
static int hf_ntlmssp_address_list = -1;
static int hf_ntlmssp_address_list_len = -1;
static int hf_ntlmssp_address_list_maxlen = -1;
static int hf_ntlmssp_address_list_offset = -1;
static int hf_ntlmssp_address_list_server_nb = -1;
static int hf_ntlmssp_address_list_domain_nb = -1;
static int hf_ntlmssp_address_list_server_dns = -1;
static int hf_ntlmssp_address_list_domain_dns = -1;
static int hf_ntlmssp_address_list_terminator = -1;
static int hf_ntlmssp_address_list_item_type = -1;
static int hf_ntlmssp_address_list_item_len = -1;
static int hf_ntlmssp_address_list_item_content = -1;
static int hf_ntlmssp_verf = -1;
static int hf_ntlmssp_verf_vers = -1;
static int hf_ntlmssp_verf_body = -1;
static int hf_ntlmssp_verf_randompad = -1;
static int hf_ntlmssp_verf_hmacmd5 = -1;
static int hf_ntlmssp_verf_crc32 = -1;
static int hf_ntlmssp_verf_sequence = -1;
static int hf_ntlmssp_decrypted_payload = -1;
static int hf_ntlmssp_ntlmv2_response = -1;
static int hf_ntlmssp_ntlmv2_response_hmac = -1;
static int hf_ntlmssp_ntlmv2_response_header = -1;
static int hf_ntlmssp_ntlmv2_response_reserved = -1;
static int hf_ntlmssp_ntlmv2_response_time = -1;
static int hf_ntlmssp_ntlmv2_response_chal = -1;
static int hf_ntlmssp_ntlmv2_response_unknown = -1;
static int hf_ntlmssp_ntlmv2_response_name = -1;
static int hf_ntlmssp_ntlmv2_response_name_type = -1;
static int hf_ntlmssp_ntlmv2_response_name_len = -1;
static int hf_ntlmssp_ntlmv2_response_restriction = -1;
static int hf_ntlmssp_ntlmv2_response_client_time = -1;

static gint ett_ntlmssp = -1;
static gint ett_ntlmssp_negotiate_flags = -1;
static gint ett_ntlmssp_string = -1;
static gint ett_ntlmssp_blob = -1;
static gint ett_ntlmssp_address_list = -1;
static gint ett_ntlmssp_address_list_item = -1;
static gint ett_ntlmssp_ntlmv2_response = -1;
static gint ett_ntlmssp_ntlmv2_response_name = -1;

/* Configuration variables */
static const char *nt_password = NULL;

#define MAX_BLOB_SIZE 256
typedef struct _ntlmssp_blob {
  guint16 length;
  guint8 contents[MAX_BLOB_SIZE];
} ntlmssp_blob;

/* Used in the conversation function */
typedef struct _ntlmssp_info {
  guint32 flags;
  int is_auth_ntlm_v2;
  rc4_state_struct rc4_state_client;
  rc4_state_struct rc4_state_server;
  guint8 sign_key_client[16];
  guint8 sign_key_server[16];
  guint32 server_dest_port;
  unsigned char server_challenge[8];
  unsigned char client_challenge[8];
  int rc4_state_initialized;
  ntlmssp_blob ntlm_response;
  ntlmssp_blob lm_response;
} ntlmssp_info;

/* If this struct exists in the payload_decrypt, then we have already
   decrypted it once */
typedef struct _ntlmssp_packet_info {
  guint8 *decrypted_payload;
  guint8 payload_len;
  guint8 verifier[16];
  gboolean payload_decrypted;
  gboolean verifier_decrypted;
} ntlmssp_packet_info;

#ifdef DEBUG_NTLMSSP
static void printnbyte(const guint8* tab,int nb,char* txt,char* txt2)
{
  int i=0;
  fprintf(stderr,"%s ",txt);
  for(i=0;i<nb;i++)
  {
    fprintf(stderr,"%02hhX ",*(tab+i));
  }
  fprintf(stderr,"%s",txt2);
}
/*
 static void printnchar(const guint8* tab,int nb,char* txt,char* txt2)
{
  int i=0;
  fprintf(stderr,"%s ",txt);
  for(i=0;i<nb;i++)
  {
    fprintf(stderr,"%c",*(tab+i));
  }
  fprintf(stderr,"%s",txt2);
}
*/
#else
static void printnbyte(const guint8* tab _U_,int nb _U_, char* txt _U_,char* txt2 _U_)
{
}
#endif
/*
 * GSlist of decrypted payloads.
 */
static GSList *decrypted_payloads;

int LEBE_Convert(int value)
{
  char a,b,c,d;
  /* Get each byte */
  a=value&0x000000FF;
  b=(value&0x0000FF00) >> 8;
  c=(value&0x00FF0000) >> 16;
  d=(value&0xFF000000) >> 24;
  return (a << 24) | (b << 16) | (c << 8) | d;
}
/*
  Perform a DES encryption with a 16 bit key and 8bit data item.
  It's in fact 3 susbsequent call to crypt_des_ecb with a 7 bit key.
  Missing bits for the key are replaced by 0;
  Returns output in response, which is expected to be 24 bytes.
*/
static int crypt_des_ecb_long(guint8 *response,
					       const guint8 *key,
					       const guint8 *data)
{
  guint8 pw21[21]; /* 21 bytes place for the needed key */

  memset(pw21, 0, sizeof(pw21));
  memcpy(pw21, key, 16);

  memset(response, 0, 24);
  /* crypt_des_ecb(data,key)*/
  crypt_des_ecb(response, data, pw21, 1);
  crypt_des_ecb(response + 8, data, pw21 + 7, 1);
  crypt_des_ecb(response + 16, data, pw21 + 14, 1);

  return 1;
}
/*
  Generate a challenge response, given an eight byte challenge and
  either the NT or the Lan Manager password hash (16 bytes).
  Returns output in response, which is expected to be 24 bytes.
*/
static int ntlmssp_generate_challenge_response(guint8 *response,
					       const guint8 *passhash,
					       const guint8 *challenge)
{
  guint8 pw21[21]; /* Password hash padded to 21 bytes */

  memset(pw21, 0x0, sizeof(pw21));
  memcpy(pw21, passhash, 16);

  memset(response, 0, 24);

  crypt_des_ecb(response, challenge, pw21, 1);
  crypt_des_ecb(response + 8, challenge, pw21 + 7, 1);
  crypt_des_ecb(response + 16, challenge, pw21 + 14, 1);

  return 1;
}


/* Ultra simple ainsi to unicode converter, will only work for ascii password ...*/
static void str_to_unicode(const char *nt_password, char *nt_password_unicode)
{
  int password_len = 0;
  int i;
  
  password_len = strlen(nt_password);
  if(nt_password_unicode != NULL)
  {
   for(i=0;i<(password_len);i++)
   {
     nt_password_unicode[i*2]=nt_password[i];
     nt_password_unicode[i*2+1]=0;
   }
  }
  nt_password_unicode[2*password_len]='\0';
}

/* This function generate the Key Exchange Key 
 * Depending on the flags this key will either be used to crypt the exported session key
 * or will be used directly as exported session key.
 * Exported session key is the key that will be used for sealing and signing communication*/

static void 
get_keyexchange_key(unsigned char keyexchangekey[16],const unsigned char sessionbasekey[16],const unsigned char lm_challenge_response[24],int flags)
{
  guint8 basekey[16];
  guint8 zeros[24];

  memset(keyexchangekey,0,16);
  memset(basekey,0,16);
  /* sessionbasekey is either derived from lm_password_hash or from nt_password_hash depending on the key type negotiated */
  memcpy(basekey,sessionbasekey,8);
  memset(basekey,0xBD,8);
  if(flags&NTLMSSP_NEGOTIATE_LM_KEY)
  {
    /*data,key*/
    crypt_des_ecb(keyexchangekey,lm_challenge_response,basekey,1);
    crypt_des_ecb(keyexchangekey+8,lm_challenge_response,basekey+7,1);
  }
  else
  {
    if(flags&NTLMSSP_REQUEST_NON_NT_SESSION)
    {
      /*People from samba tends to use the same function in this case than in the previous one but with 0 data 
       * it's not clear that it produce the good result 
       * memcpy(keyexchangekey,lm_hash,8);
       * Let's trust samba implementation it mights seem weird but they are more often rights than the spec !
       */
      memset(zeros,0,24); 
      crypt_des_ecb(keyexchangekey,zeros,basekey,3);
      crypt_des_ecb(keyexchangekey+8,zeros,basekey+7,1);
    }
    else
    {
      /* it is stated page 65 of NTLM SSP spec that sessionbasekey should be encrypted with hmac_md5 using the concact of both challenge 
       * when it's NTLM v1 + extended security but it turns out to be wrong !
       */
      memcpy(keyexchangekey,sessionbasekey,16);
    }
  }
}
static guint32
get_md4pass_list(md4_pass** p_pass_list,const char* nt_password) {
  guint32 nb_pass = 0;
  enc_key_t *ek;
  unsigned char nt_password_hash[16];
  int password_len = 0;
  char nt_password_unicode[256];
  md4_pass* pass_list;
  int i = 0;

  for(ek=enc_key_list;ek;ek=ek->next){
    if( ek->keylength == 16 ) {
      nb_pass++;
    }
  }
  memset(nt_password_hash,0,16);
  if (nt_password[0] != '\0' && ( strlen(nt_password) < 129 )) {
    nb_pass++;
    password_len = strlen(nt_password);
    str_to_unicode(nt_password,nt_password_unicode);
    crypt_md4(nt_password_hash,nt_password_unicode,password_len*2);
  }
  if( nb_pass == 0 ) {
    /* Unable to calculate the session key without a password  or if password is more than 128 char ......*/
    return 0;
  }
  i = 0;
  *p_pass_list = ep_alloc(nb_pass*sizeof(md4_pass));
  pass_list=*p_pass_list;

  if( memcmp(nt_password_hash,zeros,16) != 0 ) {
    memcpy(pass_list[i].md4,nt_password_hash,16);
    i = 1;
  }
  for(ek=enc_key_list;ek;ek=ek->next){
    if( ek->keylength == 16 ) {
      memcpy(pass_list[i].md4,ek->keyvalue,16);
      i++;
    }
  }
  return nb_pass;
}
/* Create an NTLMSSP version 2
 */
static void
create_ntlmssp_v2_key(const char *nt_password, const guint8 *serverchallenge , const guint8 *clientchallenge ,
		      guint8 *sessionkey ,const  guint8 *encryptedsessionkey , int flags , ntlmssp_blob ntlm_response, ntlmssp_blob lm_response _U_, ntlmssp_header_t *ntlmssph ) {
  char domain_name_unicode[256];
  char user_uppercase[256];
  char buf[512];
  /*guint8 md4[16];*/
  unsigned char nt_password_hash[16];
  unsigned char nt_proof[16];
  unsigned char ntowf[16];
  guint8 sessionbasekey[16];
  guint8 keyexchangekey[16];
  guint8 lm_challenge_response[24];
  guint32 i;
  guint32 j;
  rc4_state_struct rc4state;
  guint32  user_len;
  guint32 domain_len;
  md4_pass *pass_list;
  guint32 nb_pass = 0;
  int found = 0;

  /* We are going to try password encrypted in keytab as well, it's an idean of Stefan Metzmacher <metze@samba.org> 
   * The idea is to be able to test all the key of domain in once and to be able to decode the NTLM dialogs */

  memset(sessionkey, 0, 16);
  nb_pass = get_md4pass_list(&pass_list,nt_password);
  i=0;
  memset(user_uppercase,0,256);
  user_len = strlen(ntlmssph->acct_name);
  if( user_len < 129 ) {
     memset(buf,0,512);
     str_to_unicode(ntlmssph->acct_name,buf);
     for (j = 0; j < (2*user_len); j++) {
       if( buf[j] != '\0' ) {
         user_uppercase[j] = toupper(buf[j]);
       }  
     }
  }
  else {
     /* Unable to calculate the session not enought space in buffer, note this is unlikely to happen but ......*/
     return;
  }  
  domain_len = strlen(ntlmssph->domain_name);
  if( domain_len < 129 ) {
    str_to_unicode(ntlmssph->domain_name,domain_name_unicode);
  }
  else {
    /* Unable to calculate the session not enought space in buffer, note this is unlikely to happen but ......*/
    return;
  }
  while (i < nb_pass ) {
    /*fprintf(stderr,"Turn %d, ",i);*/
    memcpy(nt_password_hash,pass_list[i].md4,16);
    /*printnbyte(nt_password_hash,16,"Current NT password hash: ","\n");*/
    i++;
    /* ntowf computation */ 
    memset(buf,0,512);
    memcpy(buf,user_uppercase,user_len*2);
    memcpy(buf+user_len*2,domain_name_unicode,domain_len*2);
    md5_hmac(buf,domain_len*2+user_len*2,nt_password_hash,16,ntowf);
    /* LM response */
    memset(buf,0,512);
    memcpy(buf,serverchallenge,8);
    memcpy(buf+8,clientchallenge,8);
    md5_hmac(buf,16,ntowf,16,lm_challenge_response);
    memcpy(lm_challenge_response+16,clientchallenge,8);
    printnbyte(lm_challenge_response,24,"LM Response: ","\n");
  
    /* NT proof = First 16 bytes of NT response */
    memset(buf,0,512);
    memcpy(buf,serverchallenge,8);
    memcpy(buf+8,ntlm_response.contents+16,ntlm_response.length-16);
    md5_hmac(buf,ntlm_response.length-8,ntowf,16,nt_proof);
    printnbyte(nt_proof,16,"NT proof: ","\n");
    if( !memcmp(nt_proof,ntlm_response.contents,16) ) {
      found = 1;
      break;
    }

  }
  if( found == 0 ) {

    return;
  }
  
  md5_hmac(nt_proof,16,ntowf,16,sessionbasekey);
  get_keyexchange_key(keyexchangekey,sessionbasekey,lm_challenge_response,flags);
  /* now decrypt session key if needed and setup sessionkey for decrypting further communications */ 
  if (flags & NTLMSSP_NEGOTIATE_KEY_EXCH)
  {
    memcpy(sessionkey,encryptedsessionkey,16);
    crypt_rc4_init(&rc4state,keyexchangekey,16);
    crypt_rc4(&rc4state,sessionkey,16);
  }
  else
  {
    memcpy(sessionkey,keyexchangekey,16);
  }

}
 /* Create an NTLMSSP version 1 key 
 * That is more complicated logic and methods and user challenge as well.
 * password points to the ANSI password to encrypt, challenge points to
 * the 8 octet challenge string
 */
static void
create_ntlmssp_v1_key(const char *nt_password, const guint8 *serverchallenge, const guint8 *clientchallenge,
		      guint8 *sessionkey,const  guint8 *encryptedsessionkey, int flags, const guint8 *ref_nt_challenge_response,const guint8 *ref_lm_challenge_response)
{
  unsigned char lm_password_upper[16];
  unsigned char lm_password_hash[16];
  unsigned char nt_password_hash[16];
  unsigned char challenges_hash[16];
  unsigned char challenges_hash_first8[8];
  unsigned char challenges[16];
  guint8 md4[16];
  guint8 nb_pass = 0;
  guint8 sessionbasekey[16];
  guint8 keyexchangekey[16];
  guint8 lm_challenge_response[24];
  guint8 nt_challenge_response[24];
  rc4_state_struct rc4state;
  md5_state_t md5state; 
  char nt_password_unicode[256];
  size_t password_len;
  unsigned int i;
  int found = 0;
  md4_pass *pass_list;
  unsigned char lmhash_key[] =
    {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  
  memset(sessionkey, 0, 16);
  memset(lm_password_upper, 0, sizeof(lm_password_upper));
  /* lm auth/lm session == (!NTLM_NEGOTIATE_NT_ONLY && NTLMSSP_NEGOTIATE_LM_KEY) || ! (EXTENDED_SECURITY) || ! NTLMSSP_NEGOTIATE_NTLM*/
  /* Create a Lan Manager hash of the input password */
  if (nt_password[0] != '\0') {
    password_len = strlen(nt_password);
    /*Do not forget to free nt_password_nt*/
    str_to_unicode(nt_password,nt_password_unicode);
    crypt_md4(nt_password_hash,nt_password_unicode,password_len*2);
    /* Truncate password if too long */
    if (password_len > 16)
      password_len = 16;
    for (i = 0; i < password_len; i++) {
      lm_password_upper[i] = toupper(nt_password[i]);
    }
  }
  else
  {
    /* Unable to calculate the session key without a password ... and we will not use one for a keytab*/
    if( !(flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY )) {
      return;
    }
  }
  if((flags & NTLMSSP_NEGOTIATE_LM_KEY && !(flags & NTLMSSP_NEGOTIATE_NT_ONLY)) || !(flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY)  || !(flags & NTLMSSP_NEGOTIATE_NTLM)) {
    crypt_des_ecb(lm_password_hash, lmhash_key, lm_password_upper, 1);
    crypt_des_ecb(lm_password_hash+8, lmhash_key, lm_password_upper+7, 1);
    ntlmssp_generate_challenge_response(lm_challenge_response,
				      lm_password_hash, serverchallenge);
    memcpy(sessionbasekey,lm_password_hash,16);
  }
  else {
    
    memset(lm_challenge_response,0,24);
    if( flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY ) {
      nb_pass = get_md4pass_list(&pass_list,nt_password);
      i=0;
      while (i < nb_pass ) {
        /*fprintf(stderr,"Turn %d, ",i);*/
        memcpy(nt_password_hash,pass_list[i].md4,16);
        /*printnbyte(nt_password_hash,16,"Current NT password hash: ","\n");*/
        i++;
        memcpy(lm_challenge_response,clientchallenge,8);
        md5_init(&md5state); 
        md5_append(&md5state,serverchallenge,8);
        md5_append(&md5state,clientchallenge,8);
        md5_finish(&md5state,challenges_hash);
        memcpy(challenges_hash_first8,challenges_hash,8);
        crypt_des_ecb_long(nt_challenge_response,nt_password_hash,challenges_hash_first8);
        if( !memcmp(ref_nt_challenge_response,nt_challenge_response,24) ) {
          found = 1;
          break;
        }
      }
    }
    else {
      crypt_des_ecb_long(nt_challenge_response,nt_password_hash,serverchallenge);
      if( flags & NTLMSSP_NEGOTIATE_NT_ONLY ) {
        memcpy(lm_challenge_response,nt_challenge_response,24);
      }
      else {
        crypt_des_ecb_long(lm_challenge_response,lm_password_hash,serverchallenge);
      }
      if( !memcmp(ref_nt_challenge_response,nt_challenge_response,24) && !memcmp(ref_lm_challenge_response,lm_challenge_response,24) ) {
          found = 1;
      }    
    }
    /* So it's clearly not like this that's put into NTLMSSP doc but after some digging into samba code I'm quite confident
     * that sessionbasekey should be based md4(nt_password_hash) only in the case of some NT auth
     * Otherwise it should be lm_password_hash ...*/
    crypt_md4(md4,nt_password_hash,16);
    if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY) {
     memcpy(challenges,serverchallenge,8);
     memcpy(challenges+8,clientchallenge,8);
     /*md5_hmac(text,text_len,key,key_len,digest);*/
     md5_hmac(challenges,16,md4,16,sessionbasekey);
    }
    else {
     memcpy(sessionbasekey,md4,16);
    }  
  } 

  if( found == 0 ) {
    return;
  }


  get_keyexchange_key(keyexchangekey,sessionbasekey,lm_challenge_response,flags);
  memset(sessionkey, 0, 16);
  /*printnbyte(nt_challenge_response,24,"NT challenge response","\n");
  printnbyte(lm_challenge_response,24,"LM challenge response","\n");*/
  /* now decrypt session key if needed and setup sessionkey for decrypting further communications */ 
  if (flags & NTLMSSP_NEGOTIATE_KEY_EXCH)
  {
    memcpy(sessionkey,encryptedsessionkey,16);
    crypt_rc4_init(&rc4state,keyexchangekey,16);
    crypt_rc4(&rc4state,sessionkey,16);
  }
  else
  {
    memcpy(sessionkey,keyexchangekey,16);
  }
}
static void
get_siging_key(guint8 *sign_key_server,guint8* sign_key_client,const guint8 key[16], int keylen)
{
  md5_state_t md5state; 
  md5_state_t md5state2; 
  memset(sign_key_client,0,16);
  memset(sign_key_server,0,16);
  md5_init(&md5state); 
  md5_append(&md5state,key,keylen);
  md5_append(&md5state,CLIENT_SIGN_TEXT,strlen(CLIENT_SIGN_TEXT)+1);
  md5_finish(&md5state,sign_key_client);
  md5_init(&md5state2); 
  md5_append(&md5state2,key,keylen);
  md5_append(&md5state2,SERVER_SIGN_TEXT,strlen(SERVER_SIGN_TEXT)+1);
  md5_finish(&md5state2,sign_key_server);
 
}

/* We return either a 128 or 64 bit key
 */
static void 
get_sealing_rc4key(const guint8 exportedsessionkey[16] ,const int flags ,int *keylen ,guint8 *clientsealkey ,guint8 *serversealkey)
{
  md5_state_t md5state; 
  md5_state_t md5state2; 
  memset(clientsealkey,0,16);
  memset(serversealkey,0,16);
  memcpy(clientsealkey,exportedsessionkey,16);
  if (flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY)
  {
    if (flags & NTLMSSP_NEGOTIATE_128)
    {
      /* The exportedsessionkey has already the good length just update the length*/
      *keylen = 16;
    }
    else
    {
      if (flags & NTLMSSP_NEGOTIATE_56)
      {
        memset(clientsealkey+7,0,9);
        *keylen = 7;
      }
      else
      {
        memset(clientsealkey+5,0,11);
        *keylen = 5;
      }
    }
    memcpy(serversealkey,clientsealkey,16);
    md5_init(&md5state); 
    md5_append(&md5state,clientsealkey,*keylen);
    md5_append(&md5state,CLIENT_SEAL_TEXT,strlen(CLIENT_SEAL_TEXT)+1);
    md5_finish(&md5state,clientsealkey);
    md5_init(&md5state2); 
    md5_append(&md5state2,serversealkey,*keylen);
    md5_append(&md5state2,SERVER_SEAL_TEXT,strlen(SERVER_SEAL_TEXT)+1);
    md5_finish(&md5state2,serversealkey);
  }
  else
  {
    if (flags & NTLMSSP_NEGOTIATE_128)
    {
      /* The exportedsessionkey has already the good length just update the length*/
      *keylen = 16;
    }
    else
    {
      *keylen = 8;
      if (flags & NTLMSSP_NEGOTIATE_56)
      {
        memset(clientsealkey+7,0,9);
      }
      else
      {
        memset(clientsealkey+5,0,11);
        clientsealkey[5]=0xe5;
        clientsealkey[6]=0x38;
        clientsealkey[7]=0xb0;
      }
    }  
    serversealkey = memcpy(serversealkey,clientsealkey,*keylen);
  }
}
/* Create an NTLMSSP version 1 key.
 * password points to the ANSI password to encrypt, challenge points to
 * the 8 octet challenge string, key128 will do a 128 bit key if set to 1,
 * otherwise it will do a 40 bit key.  The result is stored in
 * sspkey (expected to be 16 octets)
 */
/* dissect a string - header area contains:
     two byte len
     two byte maxlen
     four byte offset of string in data area
  The function returns the offset at the end of the string header,
  but the 'end' parameter returns the offset of the end of the string itself
  The 'start' parameter returns the offset of the beginning of the string
*/
static int
dissect_ntlmssp_string (tvbuff_t *tvb, int offset,
			proto_tree *ntlmssp_tree,
			gboolean unicode_strings,
			int string_hf, int *start, int *end,
			const char **stringp)
{
  proto_tree *tree = NULL;
  proto_item *tf = NULL;
  gint16 string_length = tvb_get_letohs(tvb, offset);
  gint16 string_maxlen = tvb_get_letohs(tvb, offset+2);
  gint32 string_offset = tvb_get_letohl(tvb, offset+4);
  const char *string_text = NULL;
  int result_length;
  guint16 bc;

  *start = (string_offset > offset+8 ? string_offset : offset+8);
  if (0 == string_length) {
    *end = *start;
    if (ntlmssp_tree)
	    proto_tree_add_string(ntlmssp_tree, string_hf, tvb,
				  offset, 8, "NULL");
    if (stringp != NULL)
      *stringp = "";
    return offset+8;
  }

  bc = result_length = string_length;
  string_text = get_unicode_or_ascii_string(tvb, &string_offset,
					    unicode_strings, &result_length,
					    FALSE, TRUE, &bc);
  if (stringp != NULL)
    *stringp = string_text;

  if (ntlmssp_tree) {
    tf = proto_tree_add_string(ntlmssp_tree, string_hf, tvb,
			       string_offset, result_length, string_text);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_string);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_string_len,
		      tvb, offset, 2, string_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_string_maxlen,
		      tvb, offset, 2, string_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_string_offset,
		      tvb, offset, 4, string_offset);
  offset += 4;

  *end = string_offset + string_length;
  return offset;
}

/* dissect a generic blob - header area contains:
     two byte len
     two byte maxlen
     four byte offset of blob in data area
  The function returns the offset at the end of the blob header,
  but the 'end' parameter returns the offset of the end of the blob itself
*/
static int
dissect_ntlmssp_blob (tvbuff_t *tvb, int offset,
		      proto_tree *ntlmssp_tree,
		      int blob_hf, int *end, ntlmssp_blob *result)
{
  proto_item *tf = NULL;
  proto_tree *tree = NULL;
  guint16 blob_length = tvb_get_letohs(tvb, offset);
  guint16 blob_maxlen = tvb_get_letohs(tvb, offset+2);
  guint32 blob_offset = tvb_get_letohl(tvb, offset+4);
  if (0 == blob_length) {
    *end = (blob_offset > ((guint)offset)+8 ? blob_offset : ((guint)offset)+8);
    if (ntlmssp_tree)
	    proto_tree_add_text(ntlmssp_tree, tvb, offset, 8, "%s: Empty",
				proto_registrar_get_name(blob_hf));
    return offset+8;
  }

  if (ntlmssp_tree) {
    tf = proto_tree_add_item (ntlmssp_tree, blob_hf, tvb,
			      blob_offset, blob_length, FALSE);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_blob);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_blob_len,
		      tvb, offset, 2, blob_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_blob_maxlen,
		      tvb, offset, 2, blob_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_blob_offset,
		      tvb, offset, 4, blob_offset);
  offset += 4;

  *end = blob_offset + blob_length;

  if (result != NULL) {
    result->length = blob_length;
    memset(result->contents, 0, MAX_BLOB_SIZE);
    if (blob_length < MAX_BLOB_SIZE)
    {
      tvb_memcpy(tvb, result->contents, blob_offset, blob_length);
      if (blob_hf == hf_ntlmssp_auth_lmresponse && !(memcmp(tvb->real_data+blob_offset+8,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",16)))
      {
        proto_tree_add_item (ntlmssp_tree,
		       hf_ntlmssp_ntlm_client_challenge,
		       tvb, blob_offset, 8, FALSE);
      }
    }
  }

  /* If we are dissecting the NTLM response and it is a NTLMv2
     response call the appropriate dissector. */

  if (blob_hf == hf_ntlmssp_auth_ntresponse && blob_length > 24)
  {
    proto_tree_add_item (ntlmssp_tree,
	    hf_ntlmssp_ntlm_client_challenge,
	    tvb, blob_offset+32, 8, FALSE);
	  dissect_ntlmv2_response(tvb, tree, blob_offset, blob_length);
  }

  return offset;
}

static int
dissect_ntlmssp_negotiate_flags (tvbuff_t *tvb, int offset,
				 proto_tree *ntlmssp_tree,
				 guint32 negotiate_flags)
{
  proto_tree *negotiate_flags_tree = NULL;
  proto_item *tf = NULL;

  if (ntlmssp_tree) {
    tf = proto_tree_add_uint (ntlmssp_tree,
			      hf_ntlmssp_negotiate_flags,
			      tvb, offset, 4, negotiate_flags);
    negotiate_flags_tree = proto_item_add_subtree (tf, ett_ntlmssp_negotiate_flags);
  }

  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_8000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_4000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_2000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_1000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_800000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_400000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_200000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_100000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_8000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_4000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_2000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_1000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_800,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_400,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_200,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_100,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_08,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_04,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_02,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_01,
			  tvb, offset, 4, negotiate_flags);

  return (offset + 4);
}

/* Dissect a NTLM response. This is documented at
   http://ubiqx.org/cifs/SMB.html#SMB.8, para 2.8.5.3 */

/* Name types */

/*
 * XXX - the davenport document says that a type of 5 has been seen,
 * "apparently containing the 'parent' DNS domain for servers in
 * subdomains".
 */

#define NTLM_NAME_END        0x0000
#define NTLM_NAME_NB_HOST    0x0001
#define NTLM_NAME_NB_DOMAIN  0x0002
#define NTLM_NAME_DNS_HOST   0x0003
#define NTLM_NAME_DNS_DOMAIN 0x0004
#define NTLM_NAME_CLIENT_TIME 0x0007
#define NTLM_NAME_RESTRICTION 0x0008



static const value_string ntlm_name_types[] = {
	{ NTLM_NAME_END, "End of list" },
	{ NTLM_NAME_NB_HOST, "NetBIOS host name" },
	{ NTLM_NAME_NB_DOMAIN, "NetBIOS domain name" },
	{ NTLM_NAME_DNS_HOST, "DNS host name" },
	{ NTLM_NAME_DNS_DOMAIN, "DNS domain name" },

	{ NTLM_NAME_CLIENT_TIME, "Client Time" },
	{ NTLM_NAME_RESTRICTION, "Encoding restriction" },
	{ 0, NULL }
};

int
dissect_ntlmv2_response(tvbuff_t *tvb, proto_tree *tree, int offset, int len)
{
	proto_item *ntlmv2_item = NULL;
	proto_tree *ntlmv2_tree = NULL;
  const guint8 *restriction_bytes;
	/* Dissect NTLMv2 bits&pieces */

	if (tree) {
		ntlmv2_item = proto_tree_add_item(
			tree, hf_ntlmssp_ntlmv2_response, tvb,
			offset, len, TRUE);
		ntlmv2_tree = proto_item_add_subtree(
			ntlmv2_item, ett_ntlmssp_ntlmv2_response);
	}

	proto_tree_add_item(
		ntlmv2_tree, hf_ntlmssp_ntlmv2_response_hmac, tvb,
		offset, 16, TRUE);

	offset += 16;

	proto_tree_add_item(
		ntlmv2_tree, hf_ntlmssp_ntlmv2_response_header, tvb,
		offset, 4, TRUE);

	offset += 4;

	proto_tree_add_item(
		ntlmv2_tree, hf_ntlmssp_ntlmv2_response_reserved, tvb,
		offset, 4, TRUE);

	offset += 4;

	offset = dissect_nt_64bit_time(
		tvb, ntlmv2_tree, offset, hf_ntlmssp_ntlmv2_response_time);

	proto_tree_add_item(
		ntlmv2_tree, hf_ntlmssp_ntlmv2_response_chal, tvb,
		offset, 8, TRUE);

	offset += 8;

	proto_tree_add_item(
		ntlmv2_tree, hf_ntlmssp_ntlmv2_response_unknown, tvb,
		offset, 4, TRUE);

	offset += 4;

	/* Variable length list of names */

	while(1) {
		guint16 name_type = tvb_get_letohs(tvb, offset);
		guint16 name_len = tvb_get_letohs(tvb, offset + 2);
		proto_tree *name_tree = NULL;
		proto_item *name_item = NULL;
		char *name = NULL;

		if (ntlmv2_tree) {
			name_item = proto_tree_add_item(
				ntlmv2_tree, hf_ntlmssp_ntlmv2_response_name,
				tvb, offset, 0, TRUE);
			name_tree = proto_item_add_subtree(
				name_item, ett_ntlmssp_ntlmv2_response_name);
		}

		/* Dissect name header */

		proto_tree_add_item(
			name_tree, hf_ntlmssp_ntlmv2_response_name_type, tvb,
			offset, 2, TRUE);

		offset += 2;

		proto_tree_add_item(
			name_tree, hf_ntlmssp_ntlmv2_response_name_len, tvb,
			offset, 2, TRUE);

		offset += 2;

		/* Dissect name */

		switch(name_type){
		case NTLM_NAME_END:
			name = "NULL";
			proto_item_append_text(
				name_item, "%s",
				val_to_str(name_type, ntlm_name_types,
					   "Unknown"));
			break;
		case NTLM_NAME_CLIENT_TIME:
			dissect_nt_64bit_time(
				tvb, name_tree, offset,
				hf_ntlmssp_ntlmv2_response_client_time);
			proto_item_append_text(
				name_item, "Client Time");
			break;
    case NTLM_NAME_RESTRICTION:
			proto_item_append_text(
				name_item, "%s",
				val_to_str(name_type, ntlm_name_types,
					   "Unknown"));
      restriction_bytes = tvb_get_ptr(tvb, offset,name_len);
      proto_tree_add_bytes (name_tree,hf_ntlmssp_ntlmv2_response_restriction,tvb,offset,name_len,restriction_bytes);
  break;
		case NTLM_NAME_NB_HOST:
		case NTLM_NAME_NB_DOMAIN:
		case NTLM_NAME_DNS_HOST:
		case NTLM_NAME_DNS_DOMAIN:
		default:
			name = tvb_get_ephemeral_faked_unicode(
				tvb, offset, name_len / 2, TRUE);
			proto_tree_add_text(
				name_tree, tvb, offset, name_len,
				"Value: %s", name);
			proto_item_append_text(
				name_item, "%s, %s",
				val_to_str(name_type, ntlm_name_types,
					   "Unknown"), name);
			break;
		}


		offset += name_len;

		proto_item_set_len(name_item, name_len + 4);

		if (name_type == 0) /* End of list */
			break;
	}

	/*
	 * XXX - Windows puts 4 bytes of additional stuff here.
	 * Samba's smbclient doesn't.
	 * Both of them appear to be able to connect to W2K SMB
	 * servers.
	 * Should we display the rest of the response as an
	 * "extra data" item?
	 *
	 * XXX - we should also check whether we go past the length
	 * of the response.
	 */
	return offset;
}

/* tapping into ntlmssph not yet implemented */
static int
dissect_ntlmssp_negotiate (tvbuff_t *tvb, int offset, proto_tree *ntlmssp_tree, ntlmssp_header_t *ntlmssph _U_)
{
  guint32 negotiate_flags;
  int start;
  int workstation_end;
  int domain_end;

  /* NTLMSSP Negotiate Flags */
  negotiate_flags = tvb_get_letohl (tvb, offset);
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  /*
   * XXX - the davenport document says that these might not be
   * sent at all, presumably meaning the length of the message
   * isn't enough to contain them.
   */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, FALSE,
				  hf_ntlmssp_negotiate_domain,
				  &start, &workstation_end, NULL);
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, FALSE,
				  hf_ntlmssp_negotiate_workstation,
				  &start, &domain_end, NULL);

  /* XXX - two blobs after this one, sometimes? */

  return MAX(workstation_end, domain_end);
}


static int
dissect_ntlmssp_address_list (tvbuff_t *tvb, int offset,
			      proto_tree *ntlmssp_tree,
			      int *end)
{
  guint16 list_length = tvb_get_letohs(tvb, offset);
  guint16 list_maxlen = tvb_get_letohs(tvb, offset+2);
  guint32 list_offset = tvb_get_letohl(tvb, offset+4);
  guint16 item_type, item_length;
  guint32 item_offset;
  proto_item *tf = NULL;
  proto_tree *tree = NULL;
  proto_item *addr_tf = NULL;
  proto_tree *addr_tree = NULL;

  /* the address list is just a blob */
  if (0 == list_length) {
    *end = (list_offset > ((guint)offset)+8 ? list_offset : ((guint)offset)+8);
    if (ntlmssp_tree)
	    proto_tree_add_text(ntlmssp_tree, tvb, offset, 8,
				"Address List: Empty");
    return offset+8;
  }

  if (ntlmssp_tree) {
    tf = proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_address_list, tvb,
			      list_offset, list_length, FALSE);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_address_list);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_len,
		      tvb, offset, 2, list_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_maxlen,
		      tvb, offset, 2, list_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_offset,
		      tvb, offset, 4, list_offset);
  offset += 4;

  /* Now enumerate through the individual items in the list */
  item_offset = list_offset;

  while (item_offset < (list_offset + list_length)) {
    const char *text=NULL;
    guint32 content_offset;
    guint16 content_length;
    guint32 type_offset;
    guint32 len_offset;

    /* Content type */
    type_offset = item_offset;
    item_type = tvb_get_letohs(tvb, type_offset);

    /* Content length */
    len_offset = type_offset + 2;
    content_length = tvb_get_letohs(tvb, len_offset);

    /* Content value */
    content_offset = len_offset + 2;
    item_length = content_length + 4;

    /* Strings are always in Unicode regardless of the negotiated
       string type. */
    if (content_length > 0) {
      guint16 bc;
      int result_length;
      int item_offset_int;

      item_offset_int = content_offset;
      bc = content_length;
      text = get_unicode_or_ascii_string(tvb, &item_offset_int,
					 TRUE, &result_length,
					 FALSE, FALSE, &bc);
    }

    if (!text) text = ""; /* Make sure we don't blow up below */

    switch(item_type) {
    case NTLM_NAME_NB_HOST:
      addr_tf = proto_tree_add_string(tree, hf_ntlmssp_address_list_server_nb,
				      tvb, item_offset, item_length, text);
      break;
    case NTLM_NAME_NB_DOMAIN:
      addr_tf = proto_tree_add_string(tree, hf_ntlmssp_address_list_domain_nb,
				      tvb, item_offset, item_length, text);
      break;
    case NTLM_NAME_DNS_HOST:
      addr_tf = proto_tree_add_string(tree, hf_ntlmssp_address_list_server_dns,
				      tvb, item_offset, item_length, text);
      break;
    case NTLM_NAME_DNS_DOMAIN:
      addr_tf = proto_tree_add_string(tree, hf_ntlmssp_address_list_domain_dns,
				      tvb, item_offset, item_length, text);
      break;
    case NTLM_NAME_END:
      addr_tf = proto_tree_add_item(tree, hf_ntlmssp_address_list_terminator,
				    tvb, item_offset, item_length, TRUE);
      break;
    default:
      addr_tf = proto_tree_add_text(tree, tvb, item_offset, item_length, "Unknown type:0x%04x", item_type);
    }

    /* Now show the actual bytes that made up the summary line */
    addr_tree = proto_item_add_subtree (addr_tf,
					ett_ntlmssp_address_list_item);
    proto_tree_add_item (addr_tree, hf_ntlmssp_address_list_item_type,
			 tvb, type_offset, 2, TRUE);
    proto_tree_add_item (addr_tree, hf_ntlmssp_address_list_item_len,
			 tvb, len_offset, 2, TRUE);
    if (content_length > 0) {
      proto_tree_add_string(addr_tree, hf_ntlmssp_address_list_item_content,
			    tvb, content_offset, content_length, text);
    }

    item_offset += item_length;
  }

  *end = list_offset + list_length;
  return offset;
}

/* tapping into ntlmssph not yet implemented */
static int
dissect_ntlmssp_challenge (tvbuff_t *tvb, packet_info *pinfo, int offset,
			   proto_tree *ntlmssp_tree, ntlmssp_header_t *ntlmssph _U_)
{
  guint32 negotiate_flags;
  int item_start, item_end;
  int data_start, data_end;
  guint8 clientkey[16]; /* NTLMSSP cipher key for client */
  guint8 serverkey[16]; /* NTLMSSP cipher key for server*/
  ntlmssp_info *conv_ntlmssp_info = NULL;
  conversation_t *conversation;
  gboolean unicode_strings = FALSE;
  guint8 challenge[8];
  guint8 tmp[8];
  guint8 sspkey[16]; /* NTLMSSP cipher key */
  int ssp_key_len; /* Either 8 or 16 (40 bit or 128) */

  /* need to find unicode flag */
  negotiate_flags = tvb_get_letohl (tvb, offset+8);
  if (negotiate_flags & NTLMSSP_NEGOTIATE_UNICODE)
    unicode_strings = TRUE;

  /* Domain name */
  /*
   * XXX - the davenport document calls this the "Target Name",
   * presumably because non-domain targets are supported.
   */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, unicode_strings,
			 hf_ntlmssp_challenge_domain,
			 &item_start, &item_end, NULL);
  data_start = item_start;
  data_end = item_end;

  /* NTLMSSP Negotiate Flags */
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  /* NTLMSSP NT Lan Manager Challenge */
  proto_tree_add_item (ntlmssp_tree,
		       hf_ntlmssp_ntlm_server_challenge,
		       tvb, offset, 8, FALSE);

  /*
   * Store the flags and the RC4 state information with the conversation,
   * as they're needed in order to dissect subsequent messages.
   */
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				   pinfo->ptype, pinfo->srcport,
				   pinfo->destport, 0);
  if (!conversation) { /* Create one */
    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
				    pinfo->srcport, pinfo->destport, 0);
  }
  tvb_memcpy(tvb, tmp, offset, 8);
  /* We can face more than one NTLM exchange over the same couple of IP and ports ...*/
  conv_ntlmssp_info = conversation_get_proto_data(conversation, proto_ntlmssp);
  if (!conv_ntlmssp_info || memcmp(tmp,conv_ntlmssp_info->server_challenge,8) != 0) {
    conv_ntlmssp_info = se_alloc(sizeof(ntlmssp_info));
    /* Insert the flags into the conversation */
    conv_ntlmssp_info->flags = negotiate_flags;
    /* Insert the RC4 state information into the conversation */
    tvb_memcpy(tvb, challenge, offset, 8);
    tvb_memcpy(tvb, conv_ntlmssp_info->server_challenge, offset, 8);
    conv_ntlmssp_info->is_auth_ntlm_v2=0;
    /* Between the challenge and the user provided password, we can build the
       NTLMSSP key and initialize the cipher if we are not in EXTENDED SECURITY 
       in this case we need the client challenge as well*/
    /* BTW this is true just if we are in LM Authentification if not the logic is a bit different.
     * Right now it's not very clear what is LM Authentification it __seems__ to be when 
     * NEGOTIATE NT ONLY is not set and NEGOSIATE EXTENDED SECURITY is not set as well*/
    if (!(conv_ntlmssp_info->flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY))
    {
      conv_ntlmssp_info->rc4_state_initialized = 0;
      create_ntlmssp_v1_key(nt_password, conv_ntlmssp_info->server_challenge,NULL, sspkey,NULL,conv_ntlmssp_info->flags,conv_ntlmssp_info->ntlm_response.contents,conv_ntlmssp_info->lm_response.contents);
      if( memcmp(sspkey,zeros,16) != 0 ) {
        get_sealing_rc4key(sspkey,conv_ntlmssp_info->flags,&ssp_key_len,clientkey,serverkey);
        crypt_rc4_init(&conv_ntlmssp_info->rc4_state_client, sspkey, ssp_key_len);
        crypt_rc4_init(&conv_ntlmssp_info->rc4_state_server, sspkey, ssp_key_len);
        conv_ntlmssp_info->server_dest_port = pinfo->destport;
        conv_ntlmssp_info->rc4_state_initialized = 1;
      }
  
    }
    conversation_add_proto_data(conversation, proto_ntlmssp, conv_ntlmssp_info);
  }
  offset += 8;

  /* Reserved (function not completely known) */
  /*
   * XXX - SSP key?  The davenport document says
   *
   *	The context field is typically populated when Negotiate Local
   *	Call is set. It contains an SSPI context handle, which allows
   *	the client to "short-circuit" authentication and effectively
   *	circumvent responding to the challenge. Physically, the context
   *	is two long values. This is covered in greater detail later,
   *	in the "Local Authentication" section.
   *
   * It also says that that information may be omitted.
   */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_reserved,
		       tvb, offset, 8, FALSE);
  offset += 8;

  /*
   * The presence or absence of this field is not obviously correlated
   * with any flags in the previous NEGOTIATE message or in this
   * message (other than the "Workstation Supplied" and "Domain
   * Supplied" flags in the NEGOTIATE message, at least in the capture
   * I've seen - but those also correlate with the presence of workstation
   * and domain name fields, so it doesn't seem to make sense that they
   * actually *indicate* whether the subsequent CHALLENGE has an
   * address list).
   */
  if (offset < data_start) {
    offset = dissect_ntlmssp_address_list(tvb, offset, ntlmssp_tree, &item_end);
    data_end = MAX(data_end, item_end);
  }

  return MAX(offset, data_end);
}

static int
dissect_ntlmssp_auth (tvbuff_t *tvb, packet_info *pinfo, int offset,
		      proto_tree *ntlmssp_tree, ntlmssp_header_t *ntlmssph)
{
  int item_start, item_end;
  int data_start, data_end = 0;
  guint32 negotiate_flags;
  guint8 sspkey[16]; /* exported session key */
  guint8 clientkey[16]; /* NTLMSSP cipher key for client */
  guint8 serverkey[16]; /* NTLMSSP cipher key for server*/
  guint8 encryptedsessionkey[16];
  ntlmssp_blob sessionblob;
  gboolean unicode_strings = FALSE;
  ntlmssp_info *conv_ntlmssp_info = NULL;
  conversation_t *conversation;
  int ssp_key_len;
  /*
   * Get flag info from the original negotiate message, if any.
   * This is because the flag information is sometimes missing from
   * the AUTHENTICATE message, so we can't figure out whether
   * strings are Unicode or not by looking at *our* flags.
   * XXX it seems it's more from the CHALLENGE message, which is more clever in fact
   * because the server can change some flags.
   * But according to MS NTLMSSP doc it's not that simple. 
   * In case of Conection less mode AUTHENTICATE flags should be used because they
   * reprensent the choice of the client after having been informed of options of the 
   * server in the CHALLENGE message.
   * In Connection mode then the CHALLENGE flags should (must ?) be used
   */
  conv_ntlmssp_info = p_get_proto_data(pinfo->fd, proto_ntlmssp);
  if (conv_ntlmssp_info == NULL) {
    /*
     * There isn't any.  Is there any from this conversation?  If so,
     * it means this is the first time we've dissected this frame, so
     * we should give it flag info.
     */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     pinfo->destport, 0);
    if (conversation != NULL) {
      conv_ntlmssp_info = conversation_get_proto_data(conversation, proto_ntlmssp);
      if (conv_ntlmssp_info != NULL) {
      	/*
      	 * We have flag info; attach it to the frame.
      	 */
      	p_add_proto_data(pinfo->fd, proto_ntlmssp, conv_ntlmssp_info);
      }
    }
  }
  if (conv_ntlmssp_info != NULL) {
    if (conv_ntlmssp_info->flags & NTLMSSP_NEGOTIATE_UNICODE)
      unicode_strings = TRUE;
  }

  /*
   * Sometimes the session key and flags are missing.
   * Sometimes the session key is present but the flags are missing. 
   * XXX Who stay so ? Reading spec I would rather say the opposite: flags are 
   * always present, session information are always there as well but sometime 
   * session information could be null (in case of no session)
   * Sometimes they're both present.
   *
   * This does not correlate with any flags in the previous CHALLENGE
   * message, and only correlates with "Negotiate Unicode", "Workstation
   * Supplied", and "Domain Supplied" in the NEGOTIATE message - but
   * those don't make sense as flags to use to determine this.
   *
   * So we check all of the descriptors to figure out where the data
   * area begins, and if the session key or the flags would be in the
   * middle of the data area, we assume the field in question is
   * missing.
   */

  /* Lan Manager response */
  data_start = tvb_get_letohl(tvb, offset+4);
  offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				hf_ntlmssp_auth_lmresponse,
				&item_end,
				conv_ntlmssp_info == NULL ? NULL :
				    &conv_ntlmssp_info->lm_response);
  data_end = MAX(data_end, item_end);
  
  /* NTLM response */
  item_start = tvb_get_letohl(tvb, offset+4);
  offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				hf_ntlmssp_auth_ntresponse,
				&item_end,
				conv_ntlmssp_info == NULL ? NULL :
				&conv_ntlmssp_info->ntlm_response);
  if( conv_ntlmssp_info != NULL && conv_ntlmssp_info->ntlm_response.length > 24 ) {
    memcpy(conv_ntlmssp_info->client_challenge,conv_ntlmssp_info->ntlm_response.contents+32,8);
  }
  data_start = MIN(data_start, item_start);
  data_end = MAX(data_end, item_end);
  if( conv_ntlmssp_info != NULL )
  {
    if( conv_ntlmssp_info->ntlm_response.length > 24 )
    {
      conv_ntlmssp_info->is_auth_ntlm_v2=1;
    }
    else
    {
      conv_ntlmssp_info->is_auth_ntlm_v2=0;
    }
  }

  /* domain name */
  item_start = tvb_get_letohl(tvb, offset+4);
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree,
				  unicode_strings,
				  hf_ntlmssp_auth_domain,
				  &item_start, &item_end, &(ntlmssph->domain_name));
  /*ntlmssph->domain_name_len=item_end-item_start;*/
  data_start = MIN(data_start, item_start);
  data_end = MAX(data_end, item_end);

  /* user name */
  item_start = tvb_get_letohl(tvb, offset+4);
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree,
				  unicode_strings,
				  hf_ntlmssp_auth_username,
				  &item_start, &item_end, &(ntlmssph->acct_name));
  /*ntlmssph->acct_name_len=item_end-item_start;*/
  data_start = MIN(data_start, item_start);
  data_end = MAX(data_end, item_end);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, ", User: %s\\%s",
		    ntlmssph->domain_name, ntlmssph->acct_name);

  /* hostname */
  item_start = tvb_get_letohl(tvb, offset+4);
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree,
				  unicode_strings,
				  hf_ntlmssp_auth_hostname,
				  &item_start, &item_end, &(ntlmssph->host_name));
  data_start = MIN(data_start, item_start);
  data_end = MAX(data_end, item_end);
  memset(sessionblob.contents, 0, MAX_BLOB_SIZE);
  sessionblob.length = 0;
  if (offset < data_start) {
    /* Session Key */
    offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				  hf_ntlmssp_auth_sesskey,
				  &item_end, &sessionblob);
    data_end = MAX(data_end, item_end);
  }
  if( sessionblob.length != 0 ) {
    memcpy(encryptedsessionkey,sessionblob.contents,sessionblob.length);
    if (offset < data_start) {
      /* NTLMSSP Negotiate Flags */
      negotiate_flags = tvb_get_letohl (tvb, offset);
      offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
                  negotiate_flags);
    }
    /* Try to attach to an existing conversation if not then it's useless to try to do so
     * because we are missing important information (ie. server challenge)
     */
    if (conv_ntlmssp_info) {
      /* If we are in EXTENDED SECURITY then we can now initialize cipher */
      if ((conv_ntlmssp_info->flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY))
      {
        conv_ntlmssp_info->rc4_state_initialized = 0;
        if( conv_ntlmssp_info->is_auth_ntlm_v2 ) {
          create_ntlmssp_v2_key(nt_password, conv_ntlmssp_info->server_challenge,conv_ntlmssp_info->client_challenge, sspkey,encryptedsessionkey,conv_ntlmssp_info->flags,conv_ntlmssp_info->ntlm_response,conv_ntlmssp_info->lm_response,ntlmssph);
        }
        else
        {
          memcpy(conv_ntlmssp_info->client_challenge,conv_ntlmssp_info->lm_response.contents,8);
          create_ntlmssp_v1_key(nt_password, conv_ntlmssp_info->server_challenge,conv_ntlmssp_info->client_challenge, sspkey,encryptedsessionkey,conv_ntlmssp_info->flags,conv_ntlmssp_info->ntlm_response.contents,conv_ntlmssp_info->lm_response.contents);
        }
        /* ssp is the exported session key */
        if( memcmp(sspkey,zeros,16) != 0) {
          get_sealing_rc4key(sspkey,conv_ntlmssp_info->flags,&ssp_key_len,clientkey,serverkey);
          get_siging_key((guint8*)&conv_ntlmssp_info->sign_key_server,(guint8*)&conv_ntlmssp_info->sign_key_client,sspkey,ssp_key_len);
          crypt_rc4_init(&conv_ntlmssp_info->rc4_state_server, serverkey, ssp_key_len);
          crypt_rc4_init(&conv_ntlmssp_info->rc4_state_client, clientkey, ssp_key_len); 
          conv_ntlmssp_info->server_dest_port = pinfo->destport;
          conv_ntlmssp_info->rc4_state_initialized = 1;
        }
      }
     }
  }  
  return MAX(offset, data_end);
}
static guint8*
get_sign_key(packet_info *pinfo, int cryptpeer)
{
  conversation_t *conversation;
  ntlmssp_info *conv_ntlmssp_info;

  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				   pinfo->ptype, pinfo->srcport,
				   pinfo->destport, 0);
  if (conversation == NULL) {
    /* We don't have a conversation.  In this case, stop processing
       because we do not have enough info to decrypt the payload */
    return NULL;
  }
  else {
    /* We have a conversation, check for encryption state */
    conv_ntlmssp_info = conversation_get_proto_data(conversation,
						    proto_ntlmssp);
    if (conv_ntlmssp_info == NULL) {
      /* No encryption state tied to the conversation.  Therefore, we
	 cannot decrypt the payload */
      return NULL;
    }
    else {
      /* We have the encryption state in the conversation.  So return the
	 crypt state tied to the requested peer
       */
      if (cryptpeer == 1) {
	      return (guint8*)&conv_ntlmssp_info->sign_key_client;
      } else {
	      return (guint8*)&conv_ntlmssp_info->sign_key_server;
      }
    }
  }
}
/*
 * Get the encryption state tied to this conversation.  cryptpeer indicates
 * whether to retrieve the client key (1) or the server key (0) 
 */
static rc4_state_struct *
get_encrypted_state(packet_info *pinfo, int cryptpeer)
{
  conversation_t *conversation;
  ntlmssp_info *conv_ntlmssp_info;

  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				   pinfo->ptype, pinfo->srcport,
				   pinfo->destport, 0);
  if (conversation == NULL) {
    /* We don't have a conversation.  In this case, stop processing
       because we do not have enough info to decrypt the payload */
    return NULL;
  }
  else {
    /* We have a conversation, check for encryption state */
    conv_ntlmssp_info = conversation_get_proto_data(conversation,
						    proto_ntlmssp);
    if (conv_ntlmssp_info == NULL) {
      /* No encryption state tied to the conversation.  Therefore, we
	 cannot decrypt the payload */
      return NULL;
    }
    else {
      /* We have the encryption state in the conversation.  So return the
	 crypt state tied to the requested peer
       */
      if (cryptpeer == 1) {
	      return &conv_ntlmssp_info->rc4_state_client;
      } else {
	      return &conv_ntlmssp_info->rc4_state_server;
      }
    }
  }
}
void 
decrypt_data_payload(tvbuff_t *tvb, int offset, guint32 encrypted_block_length,
		 packet_info *pinfo, proto_tree *tree _U_,gpointer key);
static void
decrypt_verifier(tvbuff_t *tvb, int offset, guint32 encrypted_block_length,
		 packet_info *pinfo, proto_tree *tree,gpointer key);
/*
tvbuff_t *
dissect_ntlmssp_encrypted_payload(tvbuff_t *data_tvb,
				  tvbuff_t *auth_tvb _U_,
				  int offset,
				  packet_info *pinfo,
				  dcerpc_auth_info *auth_info _U_)*/

int
dissect_ntlmssp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
  volatile int offset = 0;
  proto_tree *volatile ntlmssp_tree = NULL;
  proto_item *tf = NULL;
  guint32 length;
  guint32 encrypted_block_length;
  guint8 key[16];
  /* the magic ntlm is the identifier of a NTLMSSP packet that's 00 00 00 01
   */
  guint32 ntlm_magic_size = 4;
  guint32 ntlm_signature_size = 8;
  guint32 ntlm_seq_size = 4;
  length = tvb_length (tvb);
  /* signature + seq + real payload */
  encrypted_block_length = length - ntlm_magic_size;

  if (encrypted_block_length < (ntlm_signature_size + ntlm_seq_size)) {
    /* Don't know why this would happen, but if it does, don't even bother
       attempting decryption/dissection */
    return offset + length;
  }

  /* Setup a new tree for the NTLMSSP payload */
  if (tree) {
    tf = proto_tree_add_item (tree,
			      hf_ntlmssp_verf,
			      tvb, offset, -1, FALSE);

    ntlmssp_tree = proto_item_add_subtree (tf,
					   ett_ntlmssp);
  }

  /*
   * Catch the ReportedBoundsError exception; the stuff we've been
   * handed doesn't necessarily run to the end of the packet, it's
   * an item inside a packet, so if it happens to be malformed (or
   * we, or a dissector we call, has a bug), so that an exception
   * is thrown, we want to report the error, but return and let
   * our caller dissect the rest of the packet.
   *
   * If it gets a BoundsError, we can stop, as there's nothing more
   * in the packet after our blob to see, so we just re-throw the
   * exception.
   */
  TRY {
    /* Version number */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_verf_vers,
			 tvb, offset, 4, TRUE);
    offset += 4;

    /* Encrypted body */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_verf_body,
			 tvb, offset, ntlm_signature_size + ntlm_seq_size, TRUE);
    tvb_memcpy(tvb, key, offset, ntlm_signature_size + ntlm_seq_size);
    /* Try to decrypt */
    decrypt_data_payload (tvb, offset+(ntlm_signature_size + ntlm_seq_size), encrypted_block_length-(ntlm_signature_size + ntlm_seq_size), pinfo, ntlmssp_tree,key);
    decrypt_verifier (tvb, offset, ntlm_signature_size + ntlm_seq_size, pinfo, ntlmssp_tree,key);
    /* let's try to hook ourselves here */

    offset += 12;
  } CATCH(BoundsError) {
    RETHROW;
  } CATCH(ReportedBoundsError) {
    show_reported_bounds_error(tvb, pinfo, tree);
  } ENDTRY;

  return offset;
}
void 
decrypt_data_payload(tvbuff_t *tvb, int offset, guint32 encrypted_block_length,
		 packet_info *pinfo, proto_tree *tree _U_,gpointer key)
{
  tvbuff_t *decr_tvb; /* Used to display decrypted buffer */
  guint8 *peer_block;
  conversation_t *conversation;
  rc4_state_struct *rc4_state;
  rc4_state_struct *rc4_state_peer;
  ntlmssp_info *conv_ntlmssp_info = NULL;
  ntlmssp_packet_info *packet_ntlmssp_info = NULL;
  ntlmssp_packet_info *stored_packet_ntlmssp_info = NULL;

  /* Check to see if we already have state for this packet */
  packet_ntlmssp_info = p_get_proto_data(pinfo->fd, proto_ntlmssp);
  if (packet_ntlmssp_info == NULL) {
    /* We don't have any packet state, so create one */
    packet_ntlmssp_info = se_alloc(sizeof(ntlmssp_packet_info));
    memset(packet_ntlmssp_info, 0, sizeof(ntlmssp_packet_info));
    p_add_proto_data(pinfo->fd, proto_ntlmssp, packet_ntlmssp_info);
  }
  if (!packet_ntlmssp_info->payload_decrypted) {
    /* Pull the challenge info from the conversation */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     pinfo->destport, 0);
    if (conversation == NULL) {
      /* There is no conversation, thus no encryption state */
      return ;
    }

    conv_ntlmssp_info = conversation_get_proto_data(conversation,
						    proto_ntlmssp);
    if (conv_ntlmssp_info == NULL) {
      /* There is no NTLMSSP state tied to the conversation */
	    return ;
    }
    if (conv_ntlmssp_info->rc4_state_initialized != 1 ) {
       /* The crypto sybsystem is not initialized.  This means that either
	         the conversation did not include a challenge, or that we do not have the right password */
       return;
    }
    if( key != NULL ){
      stored_packet_ntlmssp_info = g_hash_table_lookup(hash_packet,key);
    }
    if( stored_packet_ntlmssp_info != NULL && stored_packet_ntlmssp_info->payload_decrypted == TRUE)
    {
      /* Mat TBD fprintf(stderr,"Found a already decrypted packet\n");*/
      memcpy(packet_ntlmssp_info,stored_packet_ntlmssp_info,sizeof(ntlmssp_packet_info));
      /* Mat TBD printnbyte(packet_ntlmssp_info->decrypted_payload,encrypted_block_length,"Data: ","\n");*/
    }
    else
    {
      /* Get the pair of RC4 state structures.  One is used for to decrypt the
         payload.  The other is used to re-encrypt the payload to represent
         the peer */
      if (conv_ntlmssp_info->server_dest_port == pinfo->destport) {
        /* client */
        rc4_state = get_encrypted_state(pinfo, 1);
        rc4_state_peer = get_encrypted_state(pinfo, 0);
      } else {
        /* server */
        rc4_state = get_encrypted_state(pinfo, 0);
        rc4_state_peer = get_encrypted_state(pinfo, 1);
      }
  
      if (rc4_state == NULL ) {
        /* There is no encryption state, so we cannot decrypt */
        return ;
      }
  
      /* Store the decrypted contents in the packet state struct
         (of course at this point, they aren't decrypted yet) */
      packet_ntlmssp_info->decrypted_payload = tvb_memdup(tvb, offset,
                                                          encrypted_block_length);
      packet_ntlmssp_info->payload_len = encrypted_block_length;
      decrypted_payloads = g_slist_prepend(decrypted_payloads,
                                           packet_ntlmssp_info->decrypted_payload);
      if( key != NULL ) {
        g_hash_table_insert(hash_packet,key,packet_ntlmssp_info);
      }
  
      /* Do the decryption of the payload */
      crypt_rc4(rc4_state, packet_ntlmssp_info->decrypted_payload,
  	      encrypted_block_length);
      /* decrypt the verifier */
      /*printnchar(packet_ntlmssp_info->decrypted_payload,encrypted_block_length,"data: ","\n");*/
      /* We setup a temporary buffer so we can re-encrypt the payload after
         decryption.  This is to update the opposite peer's RC4 state 
         it's usefull when we have only one key for both conversation
         in case of KEY_EXCH we have independant key so this is not needed*/
      if( !(NTLMSSP_NEGOTIATE_KEY_EXCH & conv_ntlmssp_info->flags)) {
        peer_block = g_malloc(encrypted_block_length);
        memcpy(peer_block, packet_ntlmssp_info->decrypted_payload,
  	      encrypted_block_length);
        crypt_rc4(rc4_state_peer, peer_block, encrypted_block_length);
        g_free(peer_block);
      } 
    
      packet_ntlmssp_info->payload_decrypted = TRUE;
    }
  }

 /* Show the decrypted buffer in a new window */
  decr_tvb = tvb_new_real_data(packet_ntlmssp_info->decrypted_payload,
			       encrypted_block_length,
			       encrypted_block_length);

  tvb_set_child_real_data_tvbuff(tvb, decr_tvb);
  pinfo->gssapi_decrypted_tvb =  decr_tvb;
}
static void
dissect_ntlmssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  volatile int offset = 0;
  proto_tree *volatile ntlmssp_tree = NULL;
  proto_item *tf = NULL;
  ntlmssp_header_t *ntlmssph; 

  ntlmssph=ep_alloc(sizeof(ntlmssp_header_t));
  ntlmssph->type=0;
  ntlmssph->domain_name=NULL;
  ntlmssph->acct_name=NULL;
  ntlmssph->host_name=NULL;

  /* Setup a new tree for the NTLMSSP payload */
  if (tree) {
    tf = proto_tree_add_item (tree,
			      hf_ntlmssp,
			      tvb, offset, -1, FALSE);

    ntlmssp_tree = proto_item_add_subtree (tf,
					   ett_ntlmssp);
  }

  /*
   * Catch the ReportedBoundsError exception; the stuff we've been
   * handed doesn't necessarily run to the end of the packet, it's
   * an item inside a packet, so if it happens to be malformed (or
   * we, or a dissector we call, has a bug), so that an exception
   * is thrown, we want to report the error, but return and let
   * our caller dissect the rest of the packet.
   *
   * If it gets a BoundsError, we can stop, as there's nothing more
   * in the packet after our blob to see, so we just re-throw the
   * exception.
   */
  TRY {
    /* NTLMSSP constant */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth,
			 tvb, offset, 8, FALSE);
    offset += 8;

    /* NTLMSSP Message Type */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_message_type,
			 tvb, offset, 4, TRUE);
    ntlmssph->type = tvb_get_letohl (tvb, offset);
    offset += 4;

    if (check_col(pinfo->cinfo, COL_INFO))
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
			    val_to_str(ntlmssph->type,
				       ntlmssp_message_types,
				       "Unknown message type"));

    /* Call the appropriate dissector based on the Message Type */
    switch (ntlmssph->type) {

    case NTLMSSP_NEGOTIATE:
      offset = dissect_ntlmssp_negotiate (tvb, offset, ntlmssp_tree, ntlmssph);
      break;

    case NTLMSSP_CHALLENGE:
      offset = dissect_ntlmssp_challenge (tvb, pinfo, offset, ntlmssp_tree, ntlmssph);
      break;

    case NTLMSSP_AUTH:
      offset = dissect_ntlmssp_auth (tvb, pinfo, offset, ntlmssp_tree, ntlmssph);
      break;

    default:
      /* Unrecognized message type */
      proto_tree_add_text (ntlmssp_tree, tvb, offset, -1,
			   "Unrecognized NTLMSSP Message");
      break;
    }
  } CATCH(BoundsError) {
    RETHROW;
  } CATCH(ReportedBoundsError) {
    show_reported_bounds_error(tvb, pinfo, tree);
  } ENDTRY;

  /*tap_queue_packet(ntlmssp_tap, pinfo, ntlmssph);*/
}



/*
 * See page 45 of "DCE/RPC over SMB" by Luke Kenneth Casson Leighton.
 */
static void
decrypt_verifier(tvbuff_t *tvb, int offset, guint32 encrypted_block_length,
		 packet_info *pinfo, proto_tree *tree,gpointer key)
{
  proto_tree *decr_tree = NULL;
  proto_item *tf = NULL;
  conversation_t *conversation;
  guint8* sign_key;
  rc4_state_struct *rc4_state;
  rc4_state_struct *rc4_state_peer;
  tvbuff_t *decr_tvb; /* Used to display decrypted buffer */
  guint8 *peer_block;
  guint8 *check_buf;
  guint8 calculated_md5[16];
  ntlmssp_info *conv_ntlmssp_info = NULL;
  ntlmssp_packet_info *packet_ntlmssp_info = NULL;
  int decrypted_offset = 0;
  int sequence = 0;

  ntlmssp_packet_info *stored_packet_ntlmssp_info = NULL;
  packet_ntlmssp_info = p_get_proto_data(pinfo->fd, proto_ntlmssp);
  if (packet_ntlmssp_info == NULL) {
    /* We don't have data for this packet */
    return;
  }
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
		     pinfo->ptype, pinfo->srcport,
		     pinfo->destport, 0);
  if (conversation == NULL) {
    /* There is no conversation, thus no encryption state */
    return;
  }
  conv_ntlmssp_info = conversation_get_proto_data(conversation,
						    proto_ntlmssp);
  if (conv_ntlmssp_info == NULL) {
  /* There is no NTLMSSP state tied to the conversation */
    return;
  }

  if( key != NULL ){
    stored_packet_ntlmssp_info = g_hash_table_lookup(hash_packet,key);
  }
  if( stored_packet_ntlmssp_info != NULL && stored_packet_ntlmssp_info->verifier_decrypted == TRUE) {
      /* Mat TBD fprintf(stderr,"Found a already decrypted packet\n");*/
      /* In Theory it's aleady the case, and we should be more clever ... like just copying buffers ...*/
      packet_ntlmssp_info = stored_packet_ntlmssp_info;
  }
  else {
    if (!packet_ntlmssp_info->verifier_decrypted) {
      if (conv_ntlmssp_info->rc4_state_initialized != 1 ) {
        /* The crypto sybsystem is not initialized.  This means that either
  	 the conversation did not include a challenge, or we are doing
  	 something other than NTLMSSP v1 */
        return;
      }
      if (conv_ntlmssp_info->server_dest_port == pinfo->destport) {
        /* client talk to server */
        rc4_state = get_encrypted_state(pinfo, 1);
        sign_key = get_sign_key(pinfo,1);
        rc4_state_peer = get_encrypted_state(pinfo, 0);
      } else {
        rc4_state = get_encrypted_state(pinfo, 0);
        sign_key = get_sign_key(pinfo,0);
        rc4_state_peer = get_encrypted_state(pinfo, 1);
      }
  
      if (rc4_state == NULL || rc4_state_peer == NULL) {
        /* There is no encryption state, so we cannot decrypt */
        return;
      }
  
      /* Setup the buffer to decrypt to */
      tvb_memcpy(tvb, packet_ntlmssp_info->verifier,
  	       offset, encrypted_block_length);
      
      /*if( !(NTLMSSP_NEGOTIATE_KEY_EXCH & packet_ntlmssp_info->flags)) {*/
      if( conv_ntlmssp_info->flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY ) {
        if( (NTLMSSP_NEGOTIATE_KEY_EXCH & conv_ntlmssp_info->flags)) {
          /* The spec says that if we have have a key exchange then we have a the signature that is crypted 
           * otherwise it's just a hmac_md5(keysign,concat(message,sequence))[0..7]
           */
          crypt_rc4(rc4_state, packet_ntlmssp_info->verifier,
  	        8);
        }
        /*
         * Try to check the HMAC MD5 of the message against those calculated works great with LDAP payload but
         * don't with DCE/RPC calls.
         * Some analysis need to be done ... 
         */
        if( sign_key != NULL ) {
          check_buf = g_malloc(packet_ntlmssp_info->payload_len+4);
          tvb_memcpy(tvb, &sequence,offset+8,4);
          memcpy(check_buf,&sequence,4);
          memcpy(check_buf+4,packet_ntlmssp_info->decrypted_payload,packet_ntlmssp_info->payload_len);
          md5_hmac(check_buf,(int)(packet_ntlmssp_info->payload_len+4),sign_key,16,calculated_md5);
          /*
          printnbyte(packet_ntlmssp_info->verifier,8,"HMAC from packet: ","\n");
          printnbyte(calculated_md5,8,"HMAC            : ","\n");
          */
          g_free(check_buf);
        }
      }
      else {
        /* The packet has a PAD then a checksum then a sequence and they are encoded in this order so we can decrypt all at once */
        /* Do the actual decryption of the verifier */
        crypt_rc4(rc4_state, packet_ntlmssp_info->verifier,
  	        encrypted_block_length);
      }
  
  
  
      /* We setup a temporary buffer so we can re-encrypt the payload after
         decryption.  This is to update the opposite peer's RC4 state 
         This is not needed when we just have EXTENDED SECURITY because the signature is not crypted
         and it's also not needed when we have key exchange because server and client have independant keys */
      if( !(NTLMSSP_NEGOTIATE_KEY_EXCH & conv_ntlmssp_info->flags) && !(NTLMSSP_NEGOTIATE_EXTENDED_SECURITY & conv_ntlmssp_info->flags)) {
        peer_block = g_malloc(encrypted_block_length);
        memcpy(peer_block, packet_ntlmssp_info->verifier,
  	      encrypted_block_length);
        crypt_rc4(rc4_state_peer, peer_block, encrypted_block_length);
        g_free(peer_block);
      }
  
      /* Mark the packet as decrypted so that subsequent attempts to dissect
         the packet use the already decrypted payload instead of attempting
         to decrypt again */
      packet_ntlmssp_info->verifier_decrypted = TRUE;
    }
  }
  /* Show the decrypted buffer in a new window */
  decr_tvb = tvb_new_child_real_data(tvb, packet_ntlmssp_info->verifier,
			       encrypted_block_length,
			       encrypted_block_length);
  add_new_data_source(pinfo, decr_tvb,
		      "Decrypted NTLMSSP Verifier");

  /* Show the decrypted payload in the tree */
  tf = proto_tree_add_text(tree, decr_tvb, 0, -1,
			   "Decrypted Verifier (%d byte%s)",
			   encrypted_block_length,
			   plurality(encrypted_block_length, "", "s"));
  decr_tree = proto_item_add_subtree (tf, ett_ntlmssp);
  
  if(( conv_ntlmssp_info->flags & NTLMSSP_NEGOTIATE_EXTENDED_SECURITY )) {
    proto_tree_add_item (decr_tree, hf_ntlmssp_verf_hmacmd5,
	  	       decr_tvb, decrypted_offset, 8,TRUE);
    decrypted_offset += 8;



    /* Incrementing sequence number of DCE conversation */
   proto_tree_add_item (decr_tree, hf_ntlmssp_verf_sequence,
		         decr_tvb, decrypted_offset, 4, TRUE);
    decrypted_offset += 4;
  }
  else {

    /* RANDOM PAD usually it's 0 */
    proto_tree_add_item (decr_tree, hf_ntlmssp_verf_randompad,
	  	       decr_tvb, decrypted_offset, 4, TRUE);
    decrypted_offset += 4;

    /* CRC32 of the DCE fragment data */
    proto_tree_add_item (decr_tree, hf_ntlmssp_verf_crc32,
	  	       decr_tvb, decrypted_offset, 4, TRUE);
    decrypted_offset += 4;

    /* Incrementing sequence number of DCE conversation */
   proto_tree_add_item (decr_tree, hf_ntlmssp_verf_sequence,
		         decr_tvb, decrypted_offset, 4, TRUE);
    decrypted_offset += 4;
  }
}

/* Used when NTLMSSP is done over DCE/RPC because in this case verifier and real payload are not contigious*/
static int 
dissect_ntlmssp_payload_only(tvbuff_t *tvb, packet_info *pinfo, _U_ proto_tree *tree)
{
  volatile int offset = 0;
  proto_tree *volatile ntlmssp_tree = NULL;
  guint32 encrypted_block_length;
  /* the magic ntlm is the identifier of a NTLMSSP packet that's 00 00 00 01
   */
  encrypted_block_length = tvb_length (tvb);
  /* signature + seq + real payload */

  /* Setup a new tree for the NTLMSSP payload */
  /*
  if (tree) {
    tf = proto_tree_add_item (tree,
			      hf_ntlmssp_verf,
			      tvb, offset, -1, FALSE);

    ntlmssp_tree = proto_item_add_subtree (tf,
					   ett_ntlmssp);
  }
  */
  /*
   * Catch the ReportedBoundsError exception; the stuff we've been
   * handed doesn't necessarily run to the end of the packet, it's
   * an item inside a packet, so if it happens to be malformed (or
   * we, or a dissector we call, has a bug), so that an exception
   * is thrown, we want to report the error, but return and let
   * our caller dissect the rest of the packet.
   *
   * If it gets a BoundsError, we can stop, as there's nothing more
   * in the packet after our blob to see, so we just re-throw the
   * exception.
   */
  TRY {
    /* Version number */

    /* Try to decrypt */
    decrypt_data_payload (tvb, offset, encrypted_block_length, pinfo, ntlmssp_tree,NULL);
    /* let's try to hook ourselves here */

  } CATCH(BoundsError) {
    RETHROW;
  } CATCH(ReportedBoundsError) {
    show_reported_bounds_error(tvb, pinfo, tree);
  } ENDTRY;

  return offset;
}
/* Used when NTLMSSP is done over DCE/RPC because in this case verifier and real payload are not contigious
 * But in fact this function could be merged with wrap_dissect_ntlmssp_verf because it's only used there
 */
static int
dissect_ntlmssp_verf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  volatile int offset = 0;
  proto_tree *volatile ntlmssp_tree = NULL;
  proto_item *tf = NULL;
  guint32 verifier_length;
  guint32 encrypted_block_length;

  verifier_length = tvb_length (tvb);
  encrypted_block_length = verifier_length - 4;

  if (encrypted_block_length < 12) {
    /* Don't know why this would happen, but if it does, don't even bother
       attempting decryption/dissection */
    return offset + verifier_length;
  }

  /* Setup a new tree for the NTLMSSP payload */
  if (tree) {
    tf = proto_tree_add_item (tree,
			      hf_ntlmssp_verf,
			      tvb, offset, -1, FALSE);

    ntlmssp_tree = proto_item_add_subtree (tf,
					   ett_ntlmssp);
  }

  /*
   * Catch the ReportedBoundsError exception; the stuff we've been
   * handed doesn't necessarily run to the end of the packet, it's
   * an item inside a packet, so if it happens to be malformed (or
   * we, or a dissector we call, has a bug), so that an exception
   * is thrown, we want to report the error, but return and let
   * our caller dissect the rest of the packet.
   *
   * If it gets a BoundsError, we can stop, as there's nothing more
   * in the packet after our blob to see, so we just re-throw the
   * exception.
   */
  TRY {
    /* Version number */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_verf_vers,
			 tvb, offset, 4, TRUE);
    offset += 4;

    /* Encrypted body */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_verf_body,
			 tvb, offset, encrypted_block_length, TRUE);

    /* Try to decrypt */
    decrypt_verifier (tvb, offset, encrypted_block_length, pinfo, ntlmssp_tree,NULL);
    /* let's try to hook ourselves here */

    offset += 12;
    offset += encrypted_block_length;
  } CATCH(BoundsError) {
    RETHROW;
  } CATCH(ReportedBoundsError) {
    show_reported_bounds_error(tvb, pinfo, tree);
  } ENDTRY;

  return offset;
}

static tvbuff_t *
wrap_dissect_ntlmssp_payload_only(tvbuff_t *tvb,tvbuff_t *auth_tvb _U_,
 int offset, packet_info *pinfo,dcerpc_auth_info *auth_info _U_)
{
	tvbuff_t *data_tvb;

	data_tvb = tvb_new_subset(
		tvb, offset, tvb_length_remaining(tvb, offset),
		tvb_length_remaining(tvb, offset));
	dissect_ntlmssp_payload_only(data_tvb, pinfo, NULL);
  return pinfo->gssapi_decrypted_tvb;
}
/*
tvbuff_t *
dissect_ntlmssp_encrypted_payload(tvbuff_t *data_tvb,
				  tvbuff_t *auth_tvb _U_,
				  int offset,
				  packet_info *pinfo,
				  dcerpc_auth_info *auth_info _U_)
{
  / * gssapi_decrypted_tvb=NULL * /
  tvbuff_t *decr_tvb; / * Used to display decrypted buffer * /
  guint8 *peer_block;
  conversation_t *conversation;
  guint32 encrypted_block_length;
  rc4_state_struct *rc4_state;
  rc4_state_struct *rc4_state_peer;
  ntlmssp_info *conv_ntlmssp_info = NULL;
  ntlmssp_packet_info *packet_ntlmssp_info = NULL;
  encrypted_block_length = tvb_length_remaining (data_tvb, offset);

  fprintf(stderr,"Called dissect_ntlmssp_encrypted_payload\n");
  / * Check to see if we already have state for this packet * /
  packet_ntlmssp_info = p_get_proto_data(pinfo->fd, proto_ntlmssp);
  if (packet_ntlmssp_info == NULL) {
    / * We don't have any packet state, so create one * /
    packet_ntlmssp_info = se_alloc(sizeof(ntlmssp_packet_info));
    memset(packet_ntlmssp_info, 0, sizeof(ntlmssp_packet_info));
    p_add_proto_data(pinfo->fd, proto_ntlmssp, packet_ntlmssp_info);
  }

  if (!packet_ntlmssp_info->payload_decrypted) {
    / * Pull the challenge info from the conversation * /
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     pinfo->destport, 0);
    if (conversation == NULL) {
      / * There is no conversation, thus no encryption state * /
      return NULL;

    }
    conv_ntlmssp_info = conversation_get_proto_data(conversation,
						    proto_ntlmssp);
    if (conv_ntlmssp_info == NULL) {
    / * There is no NTLMSSP state tied to the conversation * /
    return NULL;
    }
    / * Get the pair of RC4 state structures.  One is used for to decrypt the
       payload.  The other is used to re-encrypt the payload to represent
       the peer * /
    if (conv_ntlmssp_info->server_dest_port == pinfo->destport) {
      rc4_state = get_encrypted_state(pinfo, 1);
      rc4_state_peer = get_encrypted_state(pinfo, 0);
    } else {
      rc4_state = get_encrypted_state(pinfo, 0);
      rc4_state_peer = get_encrypted_state(pinfo, 1);
    }

    if (rc4_state == NULL || rc4_state_peer == NULL) {
      / * There is no encryption state, so we cannot decrypt * /
      return NULL;
    }

    / * Store the decrypted contents in the packet state struct
       (of course at this point, they aren't decrypted yet) * /
    packet_ntlmssp_info->decrypted_payload = tvb_memdup(data_tvb, offset,
                                                        encrypted_block_length);
    decrypted_payloads = g_slist_prepend(decrypted_payloads,
                                         packet_ntlmssp_info->decrypted_payload);

    / * Do the decryption of the payload * /
    crypt_rc4(rc4_state, packet_ntlmssp_info->decrypted_payload,
	      encrypted_block_length);

    / * We setup a temporary buffer so we can re-encrypt the payload after
       decryption.  This is to update the opposite peer's RC4 state * /
    peer_block = g_malloc(encrypted_block_length);
    memcpy(peer_block, packet_ntlmssp_info->decrypted_payload,
	   encrypted_block_length);
    crypt_rc4(rc4_state_peer, peer_block, encrypted_block_length);
    g_free(peer_block);

    packet_ntlmssp_info->payload_decrypted = TRUE;
  }

  / * Show the decrypted buffer in a new window * /
  decr_tvb = tvb_new_child_real_data(data_tvb, packet_ntlmssp_info->decrypted_payload,
			       encrypted_block_length,
			       encrypted_block_length);

  offset += encrypted_block_length;

  return decr_tvb;
}
*/
static void
free_payload(gpointer decrypted_payload, gpointer user_data _U_)
{
	g_free(decrypted_payload);
}

guint g_header_hash(gconstpointer pointer) {
  guint32 crc =  ~calculate_crc32c(pointer,16,CRC32C_PRELOAD);
  /* Mat TBD fprintf(stderr,"Val: %u\n",crc);*/
  return crc;
}

gboolean g_header_equal(gconstpointer pointer1, gconstpointer pointer2) {
  if(!memcmp(pointer1,pointer2,16)) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}
  
static void
ntlmssp_init_protocol(void)
{
	/*
	 * Free the decrypted payloads, and then free the list of decrypted
	 * payloads.
	 */
	if (decrypted_payloads != NULL) {
		g_slist_foreach(decrypted_payloads, free_payload, NULL);
		g_slist_free(decrypted_payloads);
		decrypted_payloads = NULL;
	}

  if(hash_packet == NULL) {
    hash_packet = g_hash_table_new(g_header_hash,g_header_equal);
  }

}



void
proto_register_ntlmssp(void)
{

  static hf_register_info hf[] = {
    { &hf_ntlmssp,
      { "NTLMSSP", "ntlmssp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth,
      { "NTLMSSP identifier", "ntlmssp.identifier", FT_STRING, BASE_NONE, NULL, 0x0, "NTLMSSP Identifier", HFILL }},
    { &hf_ntlmssp_message_type,
      { "NTLM Message Type", "ntlmssp.messagetype", FT_UINT32, BASE_HEX, VALS(ntlmssp_message_types), 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags,
      { "Flags", "ntlmssp.negotiateflags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_01,
      { "Negotiate UNICODE", "ntlmssp.negotiateunicode", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_UNICODE, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_02,
      { "Negotiate OEM", "ntlmssp.negotiateoem", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_OEM, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_04,
      { "Request Target", "ntlmssp.requesttarget", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_REQUEST_TARGET, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_08,
      { "Request 0x00000008", "ntlmssp.negotiate00000008", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_00000008, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_10,
      { "Negotiate Sign", "ntlmssp.negotiatesign", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_SIGN, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_20,
      { "Negotiate Seal", "ntlmssp.negotiateseal", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_SEAL, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_40,
      { "Negotiate Datagram", "ntlmssp.negotiatedatagram", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_DATAGRAM, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_80,
      { "Negotiate Lan Manager Key", "ntlmssp.negotiatelmkey", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_LM_KEY, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_100,
      { "Negotiate 0x00000100", "ntlmssp.negotiate00000100", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_00000100, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_200,
      { "Negotiate NTLM key", "ntlmssp.negotiatentlm", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_NTLM, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_400,
      { "Negotiate NT Only", "ntlmssp.negotiatentonly", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_NT_ONLY, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_800,
      { "Negotiate 0x00000800", "ntlmssp.negotiate00000800", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_00000800, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_1000,
      { "Negotiate OEM Domain Supplied", "ntlmssp.negotiateoemdomainsupplied", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_2000,
      { "Negotiate OEM Workstation Supplied", "ntlmssp.negotiateoemworkstationsupplied", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_4000,
      { "Negotiate 0x00004000", "ntlmssp.negotiate00004000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_00004000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_8000,
      { "Negotiate Always Sign", "ntlmssp.negotiatealwayssign", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_10000,
      { "Target Type Domain", "ntlmssp.targettypedomain", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_TARGET_TYPE_DOMAIN, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_20000,
      { "Target Type Server", "ntlmssp.targettypeserver", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_TARGET_TYPE_SERVER, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_40000,
      { "Target Type Share", "ntlmssp.targettypeshare", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_TARGET_TYPE_SHARE, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_80000,
      { "Negotiate Extended Security", "ntlmssp.negotiatentlm2", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_EXTENDED_SECURITY, "", HFILL }}, 
    { &hf_ntlmssp_negotiate_flags_100000,
      { "Negotiate Identify", "ntlmssp.negotiateidentify", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_IDENTIFY, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_200000,
      { "Negotiate 0x00200000", "ntlmssp.negotiatent00200000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_00200000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_400000,
      { "Request Non-NT Session", "ntlmssp.requestnonntsession", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_REQUEST_NON_NT_SESSION, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_800000,
      { "Negotiate Target Info", "ntlmssp.negotiatetargetinfo", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_TARGET_INFO, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_1000000,
      { "Negotiate 0x01000000", "ntlmssp.negotiatent01000000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_01000000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_2000000,
      { "Negotiate Version", "ntlmssp.negotiateversion", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_VERSION, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_4000000,
      { "Negotiate 0x04000000", "ntlmssp.negotiatent04000000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_04000000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_8000000,
      { "Negotiate 0x08000000", "ntlmssp.negotiatent08000000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_08000000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_10000000,
      { "Negotiate 0x10000000", "ntlmssp.negotiatent10000000", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_10000000, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_20000000,
      { "Negotiate 128", "ntlmssp.negotiate128", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_128, "128-bit encryption is supported", HFILL }},
    { &hf_ntlmssp_negotiate_flags_40000000,
      { "Negotiate Key Exchange", "ntlmssp.negotiatekeyexch", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_KEY_EXCH, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_flags_80000000,
      { "Negotiate 56", "ntlmssp.negotiate56", FT_BOOLEAN, 32, TFS (&tfs_set_notset), NTLMSSP_NEGOTIATE_56, "56-bit encryption is supported", HFILL }},
    { &hf_ntlmssp_negotiate_workstation_strlen,
      { "Calling workstation name length", "ntlmssp.negotiate.callingworkstation.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_workstation_maxlen,
      { "Calling workstation name max length", "ntlmssp.negotiate.callingworkstation.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_workstation_buffer,
      { "Calling workstation name buffer", "ntlmssp.negotiate.callingworkstation.buffer", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_workstation,
      { "Calling workstation name", "ntlmssp.negotiate.callingworkstation", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_domain_strlen,
      { "Calling workstation domain length", "ntlmssp.negotiate.domain.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_domain_maxlen,
      { "Calling workstation domain max length", "ntlmssp.negotiate.domain.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_domain_buffer,
      { "Calling workstation domain buffer", "ntlmssp.negotiate.domain.buffer", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_negotiate_domain,
      { "Calling workstation domain", "ntlmssp.negotiate.domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlm_client_challenge,
      { "NTLM Client Challenge", "ntlmssp.ntlmclientchallenge", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlm_server_challenge,
      { "NTLM Server Challenge", "ntlmssp.ntlmserverchallenge", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_reserved,
      { "Reserved", "ntlmssp.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_challenge_domain,
      { "Domain", "ntlmssp.challenge.domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_domain,
      { "Domain name", "ntlmssp.auth.domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_username,
      { "User name", "ntlmssp.auth.username", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_hostname,
      { "Host name", "ntlmssp.auth.hostname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_lmresponse,
      { "Lan Manager Response", "ntlmssp.auth.lmresponse", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_ntresponse,
      { "NTLM Response", "ntlmssp.auth.ntresponse", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_auth_sesskey,
      { "Session Key", "ntlmssp.auth.sesskey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_string_len,
      { "Length", "ntlmssp.string.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_string_maxlen,
      { "Maxlen", "ntlmssp.string.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_string_offset,
      { "Offset", "ntlmssp.string.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_blob_len,
      { "Length", "ntlmssp.blob.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_blob_maxlen,
      { "Maxlen", "ntlmssp.blob.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_blob_offset,
      { "Offset", "ntlmssp.blob.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list,
      { "Address List", "ntlmssp.challenge.addresslist", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_len,
      { "Length", "ntlmssp.challenge.addresslist.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_maxlen,
      { "Maxlen", "ntlmssp.challenge.addresslist.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_offset,
      { "Offset", "ntlmssp.challenge.addresslist.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_item_type,
      { "Target item type", "ntlmssp.targetitemtype", FT_UINT16, BASE_HEX, VALS(ntlm_name_types), 0x0, NULL, HFILL }},
    { &hf_ntlmssp_address_list_item_len,
      { "Target item Length", "ntlmssp.challenge.addresslist.item.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_item_content,
      { "Target item Content", "ntlmssp.challenge.addresslist.item.content", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_ntlmssp_address_list_server_nb,
      { "Server NetBIOS Name", "ntlmssp.challenge.addresslist.servernb", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_address_list_domain_nb,
      { "Domain NetBIOS Name", "ntlmssp.challenge.addresslist.domainnb", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_address_list_server_dns,
      { "Server DNS Name", "ntlmssp.challenge.addresslist.serverdns", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_address_list_domain_dns,
      { "Domain DNS Name", "ntlmssp.challenge.addresslist.domaindns", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_address_list_terminator,
      { "List Terminator", "ntlmssp.challenge.addresslist.terminator", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_verf,
      { "NTLMSSP Verifier", "ntlmssp.verf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_verf_vers,
      { "Version Number", "ntlmssp.verf.vers", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_verf_body,
      { "Verifier Body", "ntlmssp.verf.body", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_decrypted_payload,
      { "NTLM Decrypted Payload", "ntlmssp.decrypted_payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_verf_randompad,
      { "Random Pad", "ntlmssp.verf.randompad", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_verf_crc32,
      { "Verifier CRC32", "ntlmssp.verf.crc32", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_verf_hmacmd5,
      { "HMAC MD5", "ntlmssp.verf.hmacmd5", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_verf_sequence,
      { "Sequence", "ntlmssp.verf.sequence", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlmv2_response,
      { "NTLMv2 Response", "ntlmssp.ntlmv2response", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_hmac,
      { "HMAC", "ntlmssp.ntlmv2response.hmac", FT_BYTES, BASE_NONE,  NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_header,
      { "Header", "ntlmssp.ntlmv2response.header", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_reserved,
      { "Reserved", "ntlmssp.ntlmv2response.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_time,
      { "Time", "ntlmssp.ntlmv2response.time", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_chal,
      { "Client challenge", "ntlmssp.ntlmv2response.chal", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_unknown,
      { "Unknown", "ntlmssp.ntlmv2response.unknown", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_ntlmssp_ntlmv2_response_name,
      { "Attribute", "ntlmssp.ntlmv2response.name", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlmv2_response_name_type,
      { "Attribute type", "ntlmssp.ntlmv2response.name.type", FT_UINT32, BASE_DEC, VALS(ntlm_name_types), 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlmv2_response_name_len,
      { "Value len", "ntlmssp.ntlmv2response.name.len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlmv2_response_restriction,
      { "Encoding restrictions", "ntlmssp.ntlmv2response.name.restrictions", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlmv2_response_client_time,
      { "Client Time", "ntlmssp.ntlmv2response.client_time", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }}
  };


  static gint *ett[] = {
    &ett_ntlmssp,
    &ett_ntlmssp_negotiate_flags,
    &ett_ntlmssp_string,
    &ett_ntlmssp_blob,
    &ett_ntlmssp_address_list,
    &ett_ntlmssp_address_list_item,
    &ett_ntlmssp_ntlmv2_response,
    &ett_ntlmssp_ntlmv2_response_name
  };
  module_t *ntlmssp_module;

  proto_ntlmssp = proto_register_protocol (
					   "NTLM Secure Service Provider", /* name */
					   "NTLMSSP",	/* short name */
					   "ntlmssp"	/* abbrev */
					   );
  proto_register_field_array (proto_ntlmssp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  register_init_routine(&ntlmssp_init_protocol);

  ntlmssp_module = prefs_register_protocol(proto_ntlmssp, NULL);

  prefs_register_string_preference(ntlmssp_module, "nt_password",
				   "NT Password",
				   "NT Password (used to decrypt payloads)",
				   &nt_password);

  register_dissector("ntlmssp", dissect_ntlmssp, proto_ntlmssp);
  new_register_dissector("ntlmssp_payload", dissect_ntlmssp_payload, proto_ntlmssp);
  new_register_dissector("ntlmssp_data_only", dissect_ntlmssp_payload_only, proto_ntlmssp);
  new_register_dissector("ntlmssp_verf", dissect_ntlmssp_verf, proto_ntlmssp);
}

static int wrap_dissect_ntlmssp(tvbuff_t *tvb, int offset, packet_info *pinfo,
				proto_tree *tree, guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset(
		tvb, offset, tvb_length_remaining(tvb, offset),
		tvb_length_remaining(tvb, offset));

	dissect_ntlmssp(auth_tvb, pinfo, tree);

	return tvb_length_remaining(tvb, offset);
}

static int wrap_dissect_ntlmssp_verf(tvbuff_t *tvb, int offset, packet_info *pinfo,
				     proto_tree *tree, guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset(
		tvb, offset, tvb_length_remaining(tvb, offset),
		tvb_length_remaining(tvb, offset));
	return dissect_ntlmssp_verf(auth_tvb, pinfo, tree);
}

static dcerpc_auth_subdissector_fns ntlmssp_sign_fns = {
	wrap_dissect_ntlmssp, 			/* Bind */
	wrap_dissect_ntlmssp,			/* Bind ACK */
	wrap_dissect_ntlmssp,			/* AUTH3 */
	wrap_dissect_ntlmssp_verf,		/* Request verifier */
	wrap_dissect_ntlmssp_verf,		/* Response verifier */
	NULL,			                /* Request data */
	NULL			                /* Response data */
};

static dcerpc_auth_subdissector_fns ntlmssp_seal_fns = {
	wrap_dissect_ntlmssp, 			/* Bind */
	wrap_dissect_ntlmssp,			/* Bind ACK */
	wrap_dissect_ntlmssp,			/* AUTH3 */
	wrap_dissect_ntlmssp_verf, 		/* Request verifier */
	wrap_dissect_ntlmssp_verf,		/* Response verifier */
	wrap_dissect_ntlmssp_payload_only,	/* Request data */
	wrap_dissect_ntlmssp_payload_only	/* Response data */
};

void
proto_reg_handoff_ntlmssp(void)
{
  dissector_handle_t ntlmssp_handle, ntlmssp_wrap_handle;

  /* Register protocol with the GSS-API module */

  ntlmssp_handle = find_dissector("ntlmssp");
  ntlmssp_wrap_handle = find_dissector("ntlmssp_verf");
  gssapi_init_oid("1.3.6.1.4.1.311.2.2.10", proto_ntlmssp, ett_ntlmssp,
		  ntlmssp_handle, ntlmssp_wrap_handle,
		  "NTLMSSP - Microsoft NTLM Security Support Provider");

  /* Register authenticated pipe dissector */

  /*
   * XXX - the verifiers here seem to have a version of 1 and a body of all
   * zeroes.
   *
   * XXX - DCE_C_AUTHN_LEVEL_CONNECT is, according to the DCE RPC 1.1
   * spec, upgraded to DCE_C_AUTHN_LEVEL_PKT.  Should we register
   * any other levels here?
   */
  register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_CONNECT,
				    DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP,
				    &ntlmssp_sign_fns);

  register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT,
				    DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP,
				    &ntlmssp_sign_fns);

  register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
				    DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP,
				    &ntlmssp_sign_fns);

  register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
				    DCE_C_RPC_AUTHN_PROTOCOL_NTLMSSP,
				    &ntlmssp_seal_fns);
  ntlmssp_tap = register_tap("ntlmssp");
}
