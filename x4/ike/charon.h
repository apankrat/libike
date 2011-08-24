/*
 *	This file is a part of libike library.
 *	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/libike
 */

/*
 *	The program is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

/*
 *	$Id: charon.h,v 1.8 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_CHARON_H_
#define _CPHL_CHARON_H_

/*
 *  $todo - place a mega-comment here
 *
 */
#include "x4/misc/buffer.h"
#include "x4/net/selector.h"
#include "x4/ike/const.h"
#include "x4/ike/sa.h"

/*
 *  $comment
 */
x4m_declare_struct( x4s_ike_phase1 );
x4m_declare_struct( x4s_ike_phase2 );

/*
 *  $comment
 */
x4m_struct( x4s_ike_config1 )
{
  x4s_net_link link;

  uint8   natt;             /* x4c_ike_natt_, bitmask */
  bval    aggressive;
  uint16  hash;             /* x4c_ike_a1h_  */
  uint16  cipher;           /* x4c_ike_a1e_  */
  uint16  group;            /* x4c_ike_a1g_  */
  uint16  auth;             /* x4c_ike_a1a_  */
                            
  size_t  nlen;             /* nonce_len        */
  size_t  kbits;            /* key_len for AES, Blowfish, RC5  */

  x4s_ike_sa_lifetime life; /* ignored if {0,0} */
                            
  void * userdata;
};

x4m_struct( x4s_ike_config2 )
{
  uint8  cipher;            /* x4c_ike_tr_esp_                 */
  uint16 encaps;            /* x4c_ike_a2e_                    */
  uint16 auth;              /* x4c_ike_a2a_        (none if 0) */
  uint8  ipcomp;            /* x4c_ike_tr_ipcomp_  (none if 0) */
  size_t kbits;             /* key_len for AES                 */

  size_t nlen;              /* nonce_len                       */
  uint16 group;             /* x4c_ike_a1g_      (no PFS if 0) */
                          
  x4s_net_selector    selector;
  x4s_ike_sa_lifetime lifetime;   
                          
  void * userdata;
};

/*
 *  $comment
 */
x4m_struct( x4s_ike_keys2 )
{
  uint32   spi_l, spi_r;
  x4s_buf  key_l, key_r;
};

/*
 *  $comment
 */
typedef enum
{
  x4c_ike_v1_id = 1,       /* peer's ID                  */
  x4c_ike_v1_cert_req,     /* peer's certificate request */
  x4c_ike_v1_cert,         /* peer's certificate         */
} x4e_ike_validate;

/*
 *  $comment
 */
x4m_struct( x4s_ike_config )
{
  /* 
   *  phase 1 callbacks
   */
  void    (*ph1_initiated) (void *, x4s_ike_phase1 *);
  void    (*ph1_completed) (void *);
  void    (*ph1_disposed)  (void *);
  void    (*ph1_sa_used)   (void *, uint bytes);

  bval    (*ph1_validate)  (void *, const x4s_buf *, x4e_ike_validate);

  bval    (*ph1_send)      (void *, const x4s_buf *);
  uint    (*ph1_resend)    (void *, uint seqno, uint retry, bval dejavu);
  void    (*ph1_natt)      (void *, x4s_net_link * link, bval behind_nat);

  x4s_buf (*ph1_get_psk)   (void *);                   /* preshared key     */
  x4s_buf (*ph1_get_cert)  (void *);                   /* certificate       */
  x4s_buf (*ph1_get_prikey)(void *);                   /* local private key */
  x4s_buf (*ph1_get_pubkey)(void *, const x4s_buf * ); /* peer's public key */
/*
  x4s_buf (*ph1_get_vid)(void*);
*/

  /*
   *  phase 2 callbacks
   */
  void   (*ph2_initiated)(void *, x4s_ike_phase2 *);
  void * (*ph2_responded)(void *, x4s_ike_phase2 *);
  void   (*ph2_completed)(void *, const x4s_ike_keys2 *);
  void   (*ph2_disposed) (void *);

  bval   (*ph2_validate) (void *, const x4s_ike_config2 *);

  bval   (*ph2_send)     (void *, const x4s_buf *);
  uint   (*ph2_resend)   (void *, uint seqno, uint retry, bval dejavu);

  uint32 (*ph2_get_spi)  ();            /* local SPI value   */

  /*
   *  other parameters
   */
  bval  send_initial; /* if to send INF(INITIAL-CONTACT)                */
  bval  send_ids;     /* if to always send IDcx payloads during phase 2 */
  uint  ph2_nlen;     /* default nonce length for inbound ph2 exchanges */
  uint  trace_mask;   /* OR'ed x4e_ike_trace flags */
};

/*
 *  -- API --
 */
void x4_charon_init(x4s_ike_config * );
void x4_charon_term();

bval x4_charon_init1(const x4s_ike_config1 *);
bval x4_charon_init2(const x4s_ike_config2 *, x4s_ike_phase1 *);

void x4_charon_term1(x4s_ike_phase1 *);
void x4_charon_term2(x4s_ike_phase2 *);

bval x4_charon_recv(const x4s_net_link *, x4s_buf *);
void x4_charon_tick();


#endif
