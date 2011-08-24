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
 *	$Id: phase1.h,v 1.6 2003/04/27 21:37:37 alex Exp $
 */

#ifndef _CPHL_IKE_PHASE_1_H_
#define _CPHL_IKE_PHASE_1_H_

#include "x4/crypto/hasher.h"
#include "x4/crypto/cipher.h"
#include "x4/crypto/misc.h"

#include "x4/ike/charon.h"

#include "exchange.h"

/*
 *
 */
#define x4m_sa1_established(s1) ((s1)->sa.key != 0)

#define x4c_natt_00   1
#define x4c_natt_03   2

/*
 *
 */
typedef const x4s_ike_config x4s_callbacks;

/*
 *
 */
x4m_struct( x4s_ike_data1 )
{
  x4s_buf ni;             /* initiator's nonce */
  x4s_buf nr;             /* respondes's nonce */
                          
  x4s_dh_data ke;         
                          
  x4s_buf skeyid;         /* Phase 1 keying material */
  x4s_buf skeyid_a;       
  x4s_buf skeyid_d;       
  x4s_buf skeyid_e;       
                          
  x4s_buf idi;            /* initiator's identity,  ISAKMP payload fmt */
  x4s_buf idr;            /* responder's identity,  ISAKMP payload fmt */
                          
  x4s_buf natd_l;         /* NAT-D hash, local IP/port                 */
  x4s_buf natd_r;         /* NAT-D hash, remote IP/port                */
                          
  bval cert_requested;    /* if we've requested peer's certificate     */
  x4s_buf cr;             /* peer's certificate request, ISAKMP fmt    */
  x4s_buf cert;           /* peer's certificate, x.509 DER fmt         */
};

/*
 *
 */
x4m_struct( x4s_ike_sa1 ) /* ISAKMP SA */
{                         
  x4s_hasher_alg * hasher;
  x4s_cipher_alg * cipher;

  size_t           klen;  /* key len in bytes */
  x4s_cipher_key * key;   /* data1.skeyid_e expanded into the schedule */
                          
  x4s_buf raw;            /* the body of ISAKMP SA payload */
};

/*
 *
 */
x4m_define_struct( x4s_ike_phase1 )
{
  uint8  ci[8];            /* initiator's cookie    */
  uint8  cr[8];            /* responder's cookie    */

  x4s_ike_exchange   xchg; /* processing logic      */
  x4s_callbacks    * cb;   /* callbacks block       */
  x4s_ike_sa1        sa;   /* isakmp SA information */
  x4s_ike_data1      data; /* interim Phase 1 data  */

  x4s_net_link link;
  uint8        natt;       /* NAT traversal flag    */
  bval         nated;      /* if localhost is behind NAT */

  /* internal */
  x4s_ike_phase1 * next;   /* a linked list of phase 1 sessions    */
  x4s_ike_phase2 * s2;     /* a head of the phase 2 sessions' list */
};

/*
 *
 */
void x4_ike_phase1_free(x4s_ike_phase1 *);
                                            
/*  */
x4s_ike_phase1 * x4_ike_i1_create(const x4s_ike_config1 *, 
                                  const x4s_ike_config *);
                                            
/*
 *  -- main mode, as initiator -- 
 */
bval x4_ike_m_send1(x4s_ike_exchange *);       /* phase1_i.c     */
bval x4_ike_m_recv2(x4s_ike_exchange *);       /* phase1_i.c     */
bval x4_ike_m_send3(x4s_ike_exchange *);       /* phase1_i.c     */
                                      
bval x4_ike_m_recv4_psk(x4s_ike_exchange *);   /* phase1_i_psk.c */
bval x4_ike_m_send5_psk(x4s_ike_exchange *);   /* phase1_i_psk.c */
bval x4_ike_m_recv6_psk(x4s_ike_exchange *);   /* phase1_i_psk.c */
                                      
bval x4_ike_m_recv4_sig(x4s_ike_exchange *);   /* phase1_i_sig.c */
bval x4_ike_m_send5_sig(x4s_ike_exchange *);   /* phase1_i_sig.c */
bval x4_ike_m_recv6_sig(x4s_ike_exchange *);   /* phase1_i_sig.c */

bval x4_ike_m_send7(x4s_ike_exchange *);       /* phase1_i.c     */

/*
 *  -- aggressive mode, as initiator -- 
 */
bval x4_ike_a_send1(x4s_ike_exchange *);       /* phase1_i.c     */

bval x4_ike_a_recv2_psk(x4s_ike_exchange *);   /* phase1_i_psk.c */
bval x4_ike_a_send3_psk(x4s_ike_exchange *);   /* phase1_i_psk.c */

bval x4_ike_a_recv2_sig(x4s_ike_exchange *);   /* phase1_i_sig.c */
bval x4_ike_a_send3_sig(x4s_ike_exchange *);   /* phase1_i_sig.c */


#endif

