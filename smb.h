/* smb.h
 * Defines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: smb.h,v 1.21 2001/11/18 02:51:20 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998, 1999 Gerald Combs
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

/*
 * Don't include if already included
 */

#ifndef _SMB_H
#define _SMB_H

#ifndef min
#define min(a,b) (a < b ? a : b)
#endif

#ifndef max
#define max(a,b) (a > b ? a : b)
#endif

#define SMB_PORT 139
#define NMB_PORT 137
#define DGRAM_PORT 138
#define MAX_BUF_SIZE 4096

#define DEFAULT_BACKLOG 5

#define SMBopen       0x02   /* open a file */
#define SMBcreate     0x03   /* create a file */
#define SMBclose      0x04   /* close a file */
#define SMBflush      0x05   /* flush a file */
#define SMBunlink     0x06   /* delete a file */
#define SMBmv         0x07   /* rename a file */
#define SMBgetatr     0x08   /* get file attributes */
#define SMBsetatr     0x09   /* set file attributes */
#define SMBread       0x0A   /* read from a file */
#define SMBwrite      0x0B   /* write to a file */
#define SMBlock       0x0C   /* lock a byte range */
#define SMBunlock     0x0D   /* unlock a byte range */
#define SMBctemp      0x0E   /* create a temporary file */
#define SMBmknew      0x0F   /* make a new file */
#define SMBchkpth     0x10   /* check a directory path */
#define SMBexit       0x11   /* process exit */
#define SMBlseek      0x12   /* seek */
#define SMBtcon       0x70   /* tree connect */
#define SMBtdis       0x71   /* tree disconnect */
#define SMBnegprot    0x72   /* negotiate a protocol */
#define SMBdskattr    0x80   /* get disk attributes */
#define SMBsearch     0x81   /* search a directory */
#define SMBsplopen    0xC0   /* open a print spool file */
#define SMBsplwr      0xC1   /* write to a print spool file */
#define SMBsplclose   0xC2   /* close a print spool file */
#define SMBsplretq    0xC3   /* return print queue */
#define SMBsends      0xD0   /* send a single block message */
#define SMBsendb      0xD1   /* send a broadcast message */
#define SMBfwdname    0xD2   /* forward user name */
#define SMBcancelf    0xD3   /* cancel forward */
#define SMBgetmac     0xD4   /* get a machine name */
#define SMBsendstrt   0xD5   /* send start of multi-block message */
#define SMBsendend    0xD6   /* send end of multi-block message */
#define SMBsendtxt    0xD7   /* send text of multi-block message */

/* CorePlus protocol                                        */

#define SMBlockread   0x13  /* Lock a range and read it */
#define SMBwriteunlock 0x14 /* Unlock a range and then write */
#define SMBreadbraw   0x1a  /* read a block of data without smb header ohead*/
#define SMBwritebraw  0x1d  /* write a block of data without smb header ohead*/
#define SMBwritec     0x20  /* secondary write request */
#define SMBwriteclose 0x2c  /* write a file and then close it */

/* DOS Extended Protocol                                    */

#define SMBreadBraw      0x1A   /* read block raw */
#define SMBreadBmpx      0x1B   /* read block multiplexed */
#define SMBreadBs        0x1C   /* read block (secondary response) */
#define SMBwriteBraw     0x1D   /* write block raw */
#define SMBwriteBmpx     0x1E   /* write block multiplexed */
#define SMBwriteBs       0x1F   /* write block (secondary request) */
#define SMBwriteC        0x20   /* write complete response */
#define SMBsetattrE      0x22   /* set file attributes expanded */
#define SMBgetattrE      0x23   /* get file attributes expanded */
#define SMBlockingX      0x24   /* lock/unlock byte ranges and X */
#define SMBtrans         0x25   /* transaction - name, bytes in/out */
#define SMBtranss        0x26   /* transaction (secondary request/response) */
#define SMBioctl         0x27   /* IOCTL */
#define SMBioctls        0x28   /* IOCTL  (secondary request/response) */
#define SMBcopy          0x29   /* copy */
#define SMBmove          0x2A   /* move */
#define SMBecho          0x2B   /* echo */
#define SMBopenX         0x2D   /* open and X */
#define SMBreadX         0x2E   /* read and X */
#define SMBwriteX        0x2F   /* write and X */
#define SMBsesssetupX    0x73   /* Session Set Up & X (including User Logon) */
#define SMBtconX         0x75   /* tree connect and X */
#define SMBffirst        0x82   /* find first */
#define SMBfunique       0x83   /* find unique */
#define SMBfclose        0x84   /* find close */
#define SMBinvalid       0xFE   /* invalid command */

/* Any more ? */

#define SMBdatablockID     0x01  /* A data block identifier */
#define SMBdialectID       0x02  /* A dialect id            */
#define SMBpathnameID      0x03  /* A pathname ID           */
#define SMBasciiID         0x04  /* An ascii string ID      */
#define SMBvariableblockID 0x05  /* A variable block ID     */

/* some other defines we need */

#define SMB_AMODE_WTRU      0x4000
#define SMB_AMODE_NOCACHE   0x1000
#define SMB_AMODE_COMPAT    0x0000
#define SMB_AMODE_DENYRWX   0x0010
#define SMB_AMODE_DENYW     0x0020
#define SMB_AMODE_DENYRX    0x0030
#define SMB_AMODE_DENYNONE  0x0040
#define SMB_AMODE_OPENR     0x0000
#define SMB_AMODE_OPENW     0x0001
#define SMB_AMODE_OPENRW    0x0002
#define SMB_AMODE_OPENX     0x0003
#define SMB_AMODE_FCBOPEN   0x00FF
#define SMB_AMODE_LOCUNKN   0x0000
#define SMB_AMODE_LOCMSEQ   0x0100
#define SMB_AMODE_LOCMRAN   0x0200
#define SMB_AMODE_LOCRAL    0x0300

/* Flags defines ... */

#define SMB_FLG2_NON_DOS    0x01 /* We know non dos names             */
#define SMB_FLG2_EXT_ATR    0x02 /* We know about Extended Attributes */
#define SMB_FLG2_LNG_NAM    0x04 /* Long names ?                      */

#define SMB_EOF 0
#define SMB_SMB 1

/* SMB Protocols ... Samba should be in there as well ... */

#define SMB_P_Unknown      -1        /* Hmmm, is this smart? */
#define SMB_P_Core         0
#define SMB_P_CorePlus     1
#define SMB_P_DOSLanMan1   2
#define SMB_P_LanMan1      3
#define SMB_P_DOSLanMan2   4 
#define SMB_P_LanMan2      5
#define SMB_P_DOSLanMan2_1 6
#define SMB_P_LanMan2_1    7
#define SMB_P_NT1          8

/* Error codes */

#define SMB_SUCCESS 0x00  /* All OK */
#define SMB_ERRDOS  0x01  /* DOS based error */
#define SMB_ERRSRV  0x02  /* server error, network file manager */
#define SMB_ERRHRD  0x03  /* Hardware style error */
#define SMB_ERRCMD  0x04  /* Not an SMB format command */

/* SMB X/Open error codes for the ERRDOS error class */
#define SMBE_badfunc 1             /* Invalid function (or system call) */
#define SMBE_badfile 2             /* File not found (pathname error) */
#define SMBE_badpath 3             /* Directory not found */
#define SMBE_nofids 4              /* Too many open files */
#define SMBE_noaccess 5            /* Access denied */
#define SMBE_badfid 6              /* Invalid fid */
#define SMBE_nomem 8               /* Out of memory */
#define SMBE_badmem 9              /* Invalid memory block address */
#define SMBE_badenv 10             /* Invalid environment */
#define SMBE_badaccess 12          /* Invalid open mode */
#define SMBE_baddata 13            /* Invalid data (only from ioctl call) */
#define SMBE_res 14 
#define SMBE_baddrive 15           /* Invalid drive */
#define SMBE_remcd 16              /* Attempt to delete current directory */
#define SMBE_diffdevice 17         /* rename/move across different filesystems */
#define SMBE_nofiles 18            /* no more files found in file search */
#define SMBE_badshare 32           /* Share mode on file conflict with open mode */
#define SMBE_lock 33               /* Lock request conflicts with existing lock */
#define SMBE_unsup 50              /* Request unsupported, returned by Win 95, RJS 20Jun98 */
#define SMBE_nosuchshare 67        /* Share does not exits */
#define SMBE_filexists 80          /* File in operation already exists */
#define SMBE_cannotopen 110        /* Cannot open the file specified */
#define SMBE_unknownlevel 124
#define SMBE_badpipe 230           /* Named pipe invalid */
#define SMBE_pipebusy 231          /* All instances of pipe are busy */
#define SMBE_pipeclosing 232       /* named pipe close in progress */
#define SMBE_notconnected 233      /* No process on other end of named pipe */
#define SMBE_moredata 234          /* More data to be returned */
#define SMBE_baddirectory 267      /* Invalid directory name in a path. */
#define SMBE_eas_didnt_fit 275     /* Extended attributes didn't fit */
#define SMBE_eas_nsup 282          /* Extended attributes not supported */
#define SMBE_notify_buf_small 1022 /* Buffer too small to return change notify. */
#define SMBE_unknownipc 2142
#define SMBE_noipc 66              /* don't support ipc */

/* Error codes for the ERRSRV class */

#define SMBE_error 1               /* Non specific error code */
#define SMBE_badpw 2               /* Bad password */
#define SMBE_badtype 3             /* reserved */
#define SMBE_access 4              /* No permissions to do the requested operation */
#define SMBE_invnid 5              /* tid invalid */
#define SMBE_invnetname 6          /* Invalid servername */
#define SMBE_invdevice 7           /* Invalid device */
#define SMBE_qfull 49              /* Print queue full */
#define SMBE_qtoobig 50            /* Queued item too big */
#define SMBE_qeof 51               /* EOF in print queue dump */
#define SMBE_invpfid 52            /* Invalid print file in smb_fid */
#define SMBE_smbcmd 64             /* Unrecognised command */
#define SMBE_srverror 65           /* smb server internal error */
#define SMBE_filespecs 67          /* fid and pathname invalid combination */
#define SMBE_badlink 68 
#define SMBE_badpermits 69         /* Access specified for a file is not valid */
#define SMBE_badpid 70 
#define SMBE_setattrmode 71        /* attribute mode invalid */
#define SMBE_paused 81             /* Message server paused */
#define SMBE_msgoff 82             /* Not receiving messages */
#define SMBE_noroom 83             /* No room for message */
#define SMBE_rmuns 87              /* too many remote usernames */
#define SMBE_timeout 88            /* operation timed out */
#define SMBE_noresource  89        /* No resources currently available for request. */
#define SMBE_toomanyuids 90        /* too many userids */
#define SMBE_baduid 91             /* bad userid */
#define SMBE_useMPX 250            /* temporarily unable to use raw mode, use MPX mode */
#define SMBE_useSTD 251            /* temporarily unable to use raw mode, use standard mode */
#define SMBE_contMPX 252           /* resume MPX mode */
#define SMBE_badPW 253             /* Check this out ... */ 
#define SMBE_nosupport 0xFFFF
#define SMBE_unknownsmb 22         /* from NT 3.5 response */

/* Error codes for the ERRHRD class */

#define SMBE_nowrite 19   /* read only media */
#define SMBE_badunit 20   /* Unknown device */
#define SMBE_notready 21  /* Drive not ready */
#define SMBE_badcmd 22    /* Unknown command */
#define SMBE_data 23      /* Data (CRC) error */
#define SMBE_badreq 24    /* Bad request structure length */
#define SMBE_seek 25
#define SMBE_badmedia 26
#define SMBE_badsector 27
#define SMBE_nopaper 28
#define SMBE_write 29 
#define SMBE_read 30 
#define SMBE_general 31 
#define SMBE_badshare 32 
#define SMBE_lock 33 
#define SMBE_wrongdisk 34
#define SMBE_FCBunavail 35
#define SMBE_sharebufexc 36
#define SMBE_diskfull 39

/* Flags ... CIFS 3.1.1 */

#define SMB_FLG_LCKREAD   0x01   /* Supports LockRead   */
#define SMB_FLG_CLT_BUF   0x02   /* Client Buff avail   */
#define SMB_FLG_RES       0x04   /* Reserved            */
#define SMB_FLG_CSLS_PN   0x08   /* Caseless Pathnames  */
#define SMB_FLG_CAN_PN    0x10   /* Canonical Pathnames */
#define SMB_FLG_REQ_OPL   0x20   /* Requests OPLOCKS    */
#define SMB_FLG_REQ_BOPL  0x40   /* Requests Batch OPLs */
#define SMB_FLG_REPLY     0x80   /* A reply             */

/* SMB Offsets ... */

#define SMB_FieldP(smb, off) (smb+off)

#define SMB_DEF_IDF 0x424D53FF        /* "\377SMB" */

#define SMB_hdr_idf_offset    0          /* 0xFF,'SMB' 0-3 */
#define SMB_hdr_com_offset    4          /* BYTE       4   */
#define SMB_hdr_rcls_offset   5          /* BYTE       5   */
#define SMB_hdr_reh_offset    6          /* BYTE       6   */
#define SMB_hdr_err_offset    7          /* WORD       7   */
#define SMB_hdr_reb_offset    9          /* BYTE       9   */
#define SMB_hdr_flg_offset    9          /* same as reb ...*/
#define SMB_hdr_res_offset    10         /* 7 WORDs    10  */
#define SMB_hdr_res0_offset   10         /* WORD       10  */
#define SMB_hdr_flg2_offset   10         /* WORD           */
#define SMB_hdr_res1_offset   12         /* WORD       12  */
#define SMB_hdr_res2_offset   14
#define SMB_hdr_res3_offset   16
#define SMB_hdr_res4_offset   18
#define SMB_hdr_res5_offset   20
#define SMB_hdr_res6_offset   22
#define SMB_hdr_tid_offset    24
#define SMB_hdr_pid_offset    26
#define SMB_hdr_uid_offset    28
#define SMB_hdr_mid_offset    30
#define SMB_hdr_wct_offset    32

#define SMB_hdr_len           33        /* 33 byte header?      */

#define SMB_hdr_axc_offset    33        /* AndX Command         */
#define SMB_hdr_axr_offset    34        /* AndX Reserved        */
#define SMB_hdr_axo_offset    35     /* Offset from start to WCT of AndX cmd */

/* Format of the Negotiate Protocol SMB */

#define SMB_negp_bcc_offset   33
#define SMB_negp_buf_offset   35        /* Where the buffer starts   */
#define SMB_negp_len          35        /* plus the data             */

/* Format of the Negotiate Response SMB, for CoreProtocol, LM1.2 and */
/* NT LM 0.12. wct will be 1 for CoreProtocol, 13 for LM 1.2, and 17 */
/* for NT LM 0.12                                                    */

#define SMB_negrCP_idx_offset   33        /* Response to the neg req */
#define SMB_negrCP_bcc_offset   35
#define SMB_negrLM_idx_offset   33        /* dialect index           */
#define SMB_negrLM_sec_offset   35        /* Security mode           */
#define SMB_sec_user_mask       0x01      /* 0 = share, 1 = user     */
#define SMB_sec_encrypt_mask    0x02      /* pick out encrypt        */
#define SMB_negrLM_mbs_offset   37        /* max buffer size         */
#define SMB_negrLM_mmc_offset   39        /* max mpx count           */
#define SMB_negrLM_mnv_offset   41        /* max number of VCs       */
#define SMB_negrLM_rm_offset    43        /* raw mode support bit vec*/
#define SMB_read_raw_mask       0x01
#define SMB_write_raw_mask      0x02
#define SMB_negrLM_sk_offset    45        /* session key, 32 bits    */
#define SMB_negrLM_st_offset    49        /* Current server time     */
#define SMB_negrLM_sd_offset    51        /* Current server date     */
#define SMB_negrLM_stz_offset   53        /* Server Time Zone        */
#define SMB_negrLM_ekl_offset   55        /* encryption key length   */
#define SMB_negrLM_res_offset   57        /* reserved                */
#define SMB_negrLM_bcc_offset   59        /* bcc                     */
#define SMB_negrLM_len          61        /* 61 bytes ?              */
#define SMB_negrLM_buf_offset   61        /* Where the fun begins    */

#define SMB_negrNTLM_idx_offset 33        /* Selected protocol       */
#define SMB_negrNTLM_sec_offset 35        /* Security more           */
#define SMB_negrNTLM_mmc_offset 36        /* Different format above  */
#define SMB_negrNTLM_mnv_offset 38        /* Max VCs                 */
#define SMB_negrNTLM_mbs_offset 40        /* MBS now a long          */
#define SMB_negrNTLM_mrs_offset 44        /* Max raw size            */
#define SMB_negrNTLM_sk_offset  48        /* Session Key             */
#define SMB_negrNTLM_cap_offset 52        /* Capabilities            */
#define SMB_negrNTLM_stl_offset 56        /* Server time low         */
#define SMB_negrNTLM_sth_offset 60        /* Server time high        */
#define SMB_negrNTLM_stz_offset 64        /* Server time zone        */
#define SMB_negrNTLM_ekl_offset 66        /* Encrypt key len         */
#define SMB_negrNTLM_bcc_offset 67        /* Bcc                     */
#define SMB_negrNTLM_len        69
#define SMB_negrNTLM_buf_offset 69

/* Offsets related to Tree Connect                                      */

#define SMB_tcon_bcc_offset     33
#define SMB_tcon_buf_offset     35        /* where the data is for tcon */
#define SMB_tcon_len            35        /* plus the data              */

#define SMB_tconr_mbs_offset    33        /* max buffer size         */
#define SMB_tconr_tid_offset    35        /* returned tree id        */
#define SMB_tconr_bcc_offset    37       
#define SMB_tconr_len           39 

#define SMB_tconx_axc_offset    33        /* And X Command                */
#define SMB_tconx_axr_offset    34        /* reserved                     */
#define SMB_tconx_axo_offset    35        /* Next command offset          */
#define SMB_tconx_flg_offset    37        /* Flags, bit0=1 means disc TID */
#define SMB_tconx_pwl_offset    39        /* Password length              */
#define SMB_tconx_bcc_offset    41        /* bcc                          */
#define SMB_tconx_buf_offset    43        /* buffer                       */
#define SMB_tconx_len           43        /* up to data ...               */

#define SMB_tconxr_axc_offset   33        /* Where the AndX Command is    */
#define SMB_tconxr_axr_offset   34        /* Reserved                     */
#define SMB_tconxr_axo_offset   35        /* AndX offset location         */

/* Offsets related to tree_disconnect                                  */

#define SMB_tdis_bcc_offset     33        /* bcc                     */
#define SMB_tdis_len            35        /* total len               */

#define SMB_tdisr_bcc_offset    33        /* bcc                     */
#define SMB_tdisr_len           35

/* Offsets related to Open Request                                     */

#define SMB_open_mod_offset     33        /* Mode to open with       */
#define SMB_open_atr_offset     35        /* Attributes of file      */
#define SMB_open_bcc_offset     37        /* bcc                     */
#define SMB_open_buf_offset     39        /* File name               */
#define SMB_open_len            39        /* Plus the file name      */

#define SMB_openx_axc_offset    33        /* Next command            */
#define SMB_openx_axr_offset    34        /* Reserved                */
#define SMB_openx_axo_offset    35        /* offset of next wct      */
#define SMB_openx_flg_offset    37        /* Flags, bit0 = need more info */
                                          /* bit1 = exclusive oplock */
                                          /* bit2 = batch oplock     */
#define SMB_openx_mod_offset    39        /* mode to open with       */
#define SMB_openx_atr_offset    41        /* search attributes       */
#define SMB_openx_fat_offset    43        /* File attributes         */
#define SMB_openx_tim_offset    45        /* time and date of creat  */
#define SMB_openx_ofn_offset    49        /* Open function           */
#define SMB_openx_als_offset    51        /* Space to allocate on    */
#define SMB_openx_res_offset    55        /* reserved                */
#define SMB_openx_bcc_offset    63        /* bcc                     */
#define SMB_openx_buf_offset    65        /* Where file name goes    */
#define SMB_openx_len           65

#define SMB_openr_fid_offset    33        /* FID returned            */
#define SMB_openr_atr_offset    35        /* Attributes opened with  */
#define SMB_openr_tim_offset    37        /* Last mod time of file   */
#define SMB_openr_fsz_offset    41        /* File size 4 bytes       */
#define SMB_openr_acc_offset    45        /* Access allowed          */
#define SMB_openr_bcc_offset    47
#define SMB_openr_len           49

#define SMB_openxr_axc_offset   33        /* And X command           */
#define SMB_openxr_axr_offset   34        /* reserved                */
#define SMB_openxr_axo_offset   35        /* offset to next command  */
#define SMB_openxr_fid_offset   37        /* FID returned            */
#define SMB_openxr_fat_offset   39        /* File attributes returned*/
#define SMB_openxr_tim_offset   41        /* File creation date etc  */
#define SMB_openxr_fsz_offset   45        /* Size of file            */
#define SMB_openxr_acc_offset   49        /* Access granted          */

#define SMB_clos_fid_offset     33        /* FID to close            */
#define SMB_clos_tim_offset     35        /* Last mod time           */
#define SMB_clos_bcc_offset     39        /* bcc                     */        
#define SMB_clos_len            41

/* Offsets related to Write requests                                 */

#define SMB_write_fid_offset    33        /* FID to write            */
#define SMB_write_cnt_offset    35        /* bytes to write          */
#define SMB_write_ofs_offset    37        /* location to write to    */
#define SMB_write_clf_offset    41        /* advisory count left     */
#define SMB_write_bcc_offset    43        /* bcc = data bytes + 3    */
#define SMB_write_buf_offset    45        /* Data=0x01, len, data    */
#define SMB_write_len           45        /* plus the data ...       */

#define SMB_writr_cnt_offset    33        /* Count of bytes written  */
#define SMB_writr_bcc_offset    35        /* bcc                     */
#define SMB_writr_len           37

/* Offsets related to read requests */

#define SMB_read_fid_offset     33        /* FID of file to read     */
#define SMB_read_cnt_offset     35        /* count of words to read  */
#define SMB_read_ofs_offset     37        /* Where to read from      */
#define SMB_read_clf_offset     41        /* Advisory count to go    */
#define SMB_read_bcc_offset     43
#define SMB_read_len            45

#define SMB_readr_cnt_offset    33        /* Count of bytes returned */
#define SMB_readr_res_offset    35        /* 4 shorts reserved, 8 bytes */
#define SMB_readr_bcc_offset    43        /* bcc                     */
#define SMB_readr_bff_offset    45        /* buffer format char = 0x01 */
#define SMB_readr_len_offset    46        /* buffer len              */
#define SMB_readr_len           45        /* length of the readr before data */

/* Offsets for Create file                                           */

#define SMB_creat_atr_offset    33        /* Attributes of new file ... */
#define SMB_creat_tim_offset    35        /* Time of creation           */
#define SMB_creat_dat_offset    37        /* 4004BCE :-)                */
#define SMB_creat_bcc_offset    39        /* bcc                        */
#define SMB_creat_buf_offset    41
#define SMB_creat_len           41        /* Before the data            */

#define SMB_creatr_fid_offset   33        /* FID of created file        */

/* Offsets for Delete file                                           */

#define SMB_delet_sat_offset    33        /* search attribites          */
#define SMB_delet_bcc_offset    35        /* bcc                        */
#define SMB_delet_buf_offset    37
#define SMB_delet_len           37

/* Offsets for SESSION_SETUP_ANDX for both LM and NT LM protocols    */

#define SMB_ssetpLM_mbs_offset  37        /* Max buffer Size, allow for AndX */
#define SMB_ssetpLM_mmc_offset  39        /* max multiplex count             */
#define SMB_ssetpLM_vcn_offset  41        /* VC number if new VC             */
#define SMB_ssetpLM_snk_offset  43        /* Session Key                     */
#define SMB_ssetpLM_pwl_offset  47        /* password length                 */
#define SMB_ssetpLM_res_offset  49        /* reserved                        */
#define SMB_ssetpLM_bcc_offset  53        /* bcc                             */
#define SMB_ssetpLM_len         55        /* before data ...                 */
#define SMB_ssetpLM_buf_offset  55

#define SMB_ssetpNTLM_mbs_offset 37       /* Max Buffer Size for NT LM 0.12  */
                                          /* and above                       */
#define SMB_ssetpNTLM_mmc_offset 39       /* Max Multiplex count             */
#define SMB_ssetpNTLM_vcn_offset 41       /* VC Number                       */
#define SMB_ssetpNTLM_snk_offset 43       /* Session key                     */
#define SMB_ssetpNTLM_cipl_offset 47      /* Case Insensitive PW Len         */
#define SMB_ssetpNTLM_cspl_offset 49      /* Unicode pw len                  */
#define SMB_ssetpNTLM_res_offset 51       /* reserved                        */
#define SMB_ssetpNTLM_cap_offset 55       /* server capabilities             */
#define SMB_ssetpNTLM_bcc_offset 59       /* bcc                             */
#define SMB_ssetpNTLM_len        61       /* before data                     */
#define SMB_ssetpNTLM_buf_offset 61

#define SMB_ssetpr_axo_offset  35         /* Offset of next response ...    */
#define SMB_ssetpr_act_offset  37         /* action, bit 0 = 1 => guest     */
#define SMB_ssetpr_bcc_offset  39         /* bcc                            */
#define SMB_ssetpr_buf_offset  41         /* Native OS etc                  */

/* Offsets for SMB create directory                                         */

#define SMB_creatdir_bcc_offset 33        /* only a bcc here                */
#define SMB_creatdir_buf_offset 35        /* Where things start             */
#define SMB_creatdir_len        35

/* Offsets for SMB delete directory                                         */

#define SMB_deletdir_bcc_offset 33        /* only a bcc here                */
#define SMB_deletdir_buf_offset 35        /* where things start             */
#define SMB_deletdir_len        35

/* Offsets for SMB check directory                                          */

#define SMB_checkdir_bcc_offset 33        /* Only a bcc here                */
#define SMB_checkdir_buf_offset 35        /* where things start             */
#define SMB_checkdir_len        35

/* Offsets for SMB search                                                   */

#define SMB_search_mdc_offset   33        /* Max Dir ents to return         */
#define SMB_search_atr_offset   35        /* Search attributes              */
#define SMB_search_bcc_offset   37        /* bcc                            */
#define SMB_search_buf_offset   39        /* where the action is            */
#define SMB_search_len          39

#define SMB_searchr_dec_offset  33        /* Dir ents returned              */
#define SMB_searchr_bcc_offset  35        /* bcc                            */
#define SMB_searchr_buf_offset  37        /* Where the action starts        */
#define SMB_searchr_len         37        /* before the dir ents            */

#define SMB_searchr_dirent_len  43        /* 53 bytes                       */

/* Defines for SMB getatr call                                              */

#define SMB_getatr_bcc_offset 33        /* Only a bcc here           */
#define SMB_getatr_buf_offset 35        /* Where the buffer starts   */
#define SMB_getatr_len        35

#define SMB_getatrr_atr_offset 33       /* Attr offset               */
#define SMB_getatrr_tim_offset 35       /* Time1 field offset        */
#define SMB_getatrr_siz_offset 39       /* Size offset               */
#define SMB_getatrr_mbz_offset 43       /* MBZ Field                 */
#define SMB_getatrr_bcc_offset 53       /* bcc = 0                   */
#define SMB_getatrr_len        55

/* Defines the setatr call                                           */

#define SMB_setatr_atr_offset  33      /* Attribute offset           */
#define SMB_setatr_tim_offset  35      /* Time1 offset               */
#define SMB_setatr_siz_offset  39      /* size offset                */
#define SMB_setatr_mbz_offset  43      
#define SMB_setatr_bcc_offset  53      /* Where bcc is               */
#define SMB_setatr_buf_offset  55      /* Where the data goes        */
#define SMB_setatr_len         55      /* Plus the params            */

#define SMB_setatrr_bcc        33      /* Nothing much here          */
#define SMB_setatrr_len        35

/* Defines for SMB transact and transact2 calls                             */

#define SMB_trans_tpc_offset    33        /* Total param count              */
#define SMB_trans_tdc_offset    35        /* total Data count               */
#define SMB_trans_mpc_offset    37        /* Max params bytes to return     */
#define SMB_trans_mdc_offset    39        /* Max data bytes to return       */
#define SMB_trans_msc_offset    41        /* Max setup words to return      */
#define SMB_trans_rs1_offset    42        /* Reserved byte                  */
#define SMB_trans_flg_offset    43        /* flags                          */
#define SMB_trans_tmo_offset    45        /* Timeout, long                  */
#define SMB_trans_rs2_offset    49        /* Next reserved                  */
#define SMB_trans_pbc_offset    51        /* Param Byte count in buf        */
#define SMB_trans_pbo_offset    53        /* Offset to param bytes          */
#define SMB_trans_dbc_offset    55        /* Data byte count in buf         */
#define SMB_trans_dbo_offset    57        /* Data byte offset               */
#define SMB_trans_suc_offset    59        /* Setup count - byte             */
#define SMB_trans_rs3_offset    60        /* Reserved to pad ...            */
#define SMB_trans_len           61        /* Up to setup, still need bcc    */

#define SMB_transr_tpc_offset   33        /* Total param bytes returned     */
#define SMB_transr_tdc_offset   35
#define SMB_transr_rs1_offset   37
#define SMB_transr_pbc_offset   39
#define SMB_transr_pbo_offset   41
#define SMB_transr_pdi_offset   43        /* parameter displacement         */
#define SMB_transr_dbc_offset   45
#define SMB_transr_dbo_offset   47
#define SMB_transr_ddi_offset   49
#define SMB_transr_suc_offset   51
#define SMB_transr_rs2_offset   52
#define SMB_transr_len          53

/* Bit masks for SMB Capabilities ...                       */

#define SMB_cap_raw_mode         0x0001
#define SMB_cap_mpx_mode         0x0002
#define SMB_cap_unicode          0x0004
#define SMB_cap_large_files      0x0008
#define SMB_cap_nt_smbs          0x0010
#define SMB_rpc_remote_apis      0x0020
#define SMB_cap_nt_status        0x0040
#define SMB_cap_level_II_oplocks 0x0080
#define SMB_cap_lock_and_read    0x0100
#define SMB_cap_nt_find          0x0200

/* SMB LANMAN api call defines */

#define SMB_LMapi_SetUserInfo     0x0072
#define SMB_LMapi_UserPasswordSet 0x0073

/*
 * The information we need to save about a request in order to show the
 * frame number of the request in the dissection of the reply.
 */
typedef struct {
	guint32 frame_req, frame_res;
	void *extra_info;
} smb_saved_info_t;

/*
 * The information we need to save about a Transaction request in order
 * to dissect the reply; this includes information for use by the
 * Remote API and Mailslot dissectors.
 * XXX - have an additional data structure hung off of this by the
 * subdissectors?
 */
typedef struct {
	int subcmd;
	int trans_subcmd;
	guint16 lanman_cmd;
	guchar *param_descrip;  /* Keep these descriptors around */
	guchar *data_descrip;
	guchar *aux_data_descrip;
	int info_level;
} smb_transact_info_t;

/*
 * Subcommand type.
 */
#define TRANSACTION_PIPE	0
#define TRANSACTION_MAILSLOT	1

typedef struct smb_info {
  int cmd, mid;
  gboolean unicode;		/* Are strings in this SMB Unicode? */
  gboolean request;		/* Is this a request? */
  gboolean unidir;
  int info_count;
  smb_saved_info_t *sip;	/* smb_saved_info_t, if any, for this */
} smb_info_t;

#endif
