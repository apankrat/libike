/*
 *	This file is a part of libike library.
 *	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/libike
 */

/*
 *	The library is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

/*
 *	$Id: phase1.c,v 1.6 2003/04/27 21:37:37 alex Exp $
 */

#include "phase1.h"

#include "x4/core/bswap.h"
#include "x4/crypto/random.h"

#include "utils.h"

/*
 *  -- local functions --
 */
static void  _s1_format_sa(x4s_ike_phase1 * s1, const x4s_ike_config1 * s1c);
static uint8 _s1_xchg_on_advance(x4s_ike_exchange *);
static void  _s1_setup_exchange(x4s_ike_phase1 * s1, bval, uint16, void *);

extern x4s_ike_exchange x4v_ike_xchg_m_i_psk;
extern x4s_ike_exchange x4v_ike_xchg_m_i_sig;
extern x4s_ike_exchange x4v_ike_xchg_a_i_psk;
extern x4s_ike_exchange x4v_ike_xchg_a_i_sig;

/*
 *
 */
void x4_ike_phase1_free(x4s_ike_phase1 * s1)
{
  x4_assert(s1);
  x4_assert(! s1->s2);

  /*  */
  x4_ike_exchange_free(&s1->xchg);

  x4_free(s1->sa.key);
  x4_buf_free(&s1->sa.raw);

  x4_buf_free(&s1->data.ni);
  x4_buf_free(&s1->data.nr);

  x4_dh_data_free(&s1->data.ke);

  x4_buf_free(&s1->data.skeyid);
  x4_buf_free(&s1->data.skeyid_a);
  x4_buf_free(&s1->data.skeyid_d);
  x4_buf_free(&s1->data.skeyid_e);

  x4_buf_free(&s1->data.idi);
  x4_buf_free(&s1->data.idr);

  x4_buf_free(&s1->data.natd_l);
  x4_buf_free(&s1->data.natd_r);

  x4_buf_free(&s1->data.cr);
  x4_buf_free(&s1->data.cert);
}

/*  */
x4s_ike_phase1 * x4_ike_i1_create(const x4s_ike_config1 * s1c, 
                                  const x4s_ike_config * cfg)
{
  x4s_ike_phase1 * s1 = 0;
  
  /* validate context */
  x4_assert(s1c);

  /* validate paramters */
  x4_assert(8 <= s1c->nlen && s1c->nlen <= 256);

  /* allocate session object */
  s1 = (x4s_ike_phase1*)x4_mallocz(sizeof(x4s_ike_phase1));
  x4_assert(s1);

  /* copy some params */
  s1->link = s1c->link;
  s1->natt = s1c->natt;
  s1->cb = cfg;

  /* generate nonce */
  x4_buf_resize(&s1->data.ni, s1c->nlen);
  x4_randomb(&s1->data.ni);

  /* assign hashing alg */
  s1->sa.hasher = x4_ike_select_hasher(s1c->hash);
  x4_assert(s1->sa.hasher);

  /* assign encryption alg */
  s1->sa.cipher = x4_ike_select_cipher(s1c->cipher);
  x4_assert(s1->sa.cipher);

  s1->sa.klen  = s1->sa.cipher->init_kl(s1c->kbits)/8;
  x4_assert(s1->sa.klen);
  
  /* assign oakley DH group */
  s1->data.ke.p = x4_ike_select_prime(s1c->group);
  x4_assert(s1->data.ke.p.len);

  x4_buf_attach(&s1->data.ke.g, x4v_ike_modp_exp, sizeof(x4v_ike_modp_exp));

  /* setup handlers based on the auth mode */
  _s1_setup_exchange(s1, s1c->aggressive, s1c->auth, s1c->userdata);

  /* generate i-cookie */
  x4_random(s1->ci, 8);

  /* format SA payload (s1->sa.raw) */
  _s1_format_sa(s1, s1c);

  return s1;
}

/*
 *  -- local methods --
 */
void _s1_format_sa(x4s_ike_phase1 * s1, const x4s_ike_config1 * s1c)
{
  x4s_ike_sa_payload     sa = { 0 };
  x4s_ike_sa_proposal  * pr = sa.pr;
  x4s_ike_sa_transform * tr = pr->tr;
  x4s_ike_sa_attribute * a = tr->attr;

  /*  */
  x4_assert(s1 && s1c);

  /*  */
  sa.doi = x4c_ike_doi_ipsec;
  sa.sit = x4c_ike_sit_identity_only;

  pr->index = 1;
  pr->proto = x4c_ike_proto_isakmp;
/*x4_buf_attach(&pr->spi, &s1->ci, 16);*/

  tr->index = 1;
  tr->type  = x4c_ike_tr_isakmp_key_ike;
  
  a->type = x4c_ike_a1_encryption_algorithm;
  a->val  = s1c->cipher;
  a++;

  a->type = x4c_ike_a1_hash_algorithm;
  a->val  = s1c->hash;
  a++;

  a->type = x4c_ike_a1_auth_method;
  a->val  = s1c->auth;
  a++;

  a->type = x4c_ike_a1_group_description;
  a->val  = s1c->group;
  a++;

  if (s1c->kbits)
  {
    a->type = x4c_ike_a1_key_length;
    a->val  = s1c->kbits;
    a++;
  }

  if (s1c->life.seconds)
  {
    a->type = x4c_ike_a1_life_type;
    a->val  = x4c_ike_a1l_seconds;
    a++;
    a->type = x4c_ike_a1_life_duration;
    a->val  = s1c->life.seconds;
    a++;
  }

  if (s1c->life.kbytes)
  {
    a->type = x4c_ike_a1_life_type;
    a->val  = x4c_ike_a1l_kilobytes;
    a++;
    a->type = x4c_ike_a1_life_duration;
    a->val  = s1c->life.kbytes;
    a++;
  }

  x4_ike_sa_pack(&sa, &s1->sa.raw);
}

/*
 *
 */
uint8 _s1_xchg_on_advance(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  uint seqno = xchg->seqno;
  
  /*  */
  if (xchg->et == x4c_ike_et_aggressive)
  {
    x4_assert(xchg->seqno < 3);
    if (++xchg->seqno == 3)
      xchg->seqno = x4c_ike_state_completed;
  }
  else
  if (xchg->et == x4c_ike_et_main_mode)
  {
    if (xchg->initiator && s1->cb->send_initial)
    {
      x4_assert(xchg->seqno < 7);
      if (++xchg->seqno == 7)
        xchg->seqno = x4c_ike_state_completed;
    }
    else
    {
      /* $hmm - we dont need no stinky notify.initial_contact */
      x4_assert(xchg->seqno < 6);  
      if (++xchg->seqno == 6)
        xchg->seqno = x4c_ike_state_completed;
    }
  }
  else
    x4_assert(0);

  /*  */
  if (xchg->seqno == x4c_ike_state_completed)
    s1->cb->ph1_completed(xchg->userdata);

  return xchg->seqno;
}

/*
 *
 */
void _s1_setup_exchange(x4s_ike_phase1 * s1, bval agg, 
                        uint16 auth, void * context)
{
  x4s_ike_exchange * xchg = &s1->xchg;

  x4_assert(s1);

  /*  */
  xchg->et = 0;
  if (! agg)
    switch (auth)
    {
    case x4c_ike_a1a_preshared: *xchg = x4v_ike_xchg_m_i_psk; break;
    case x4c_ike_a1a_rsa_sig:   *xchg = x4v_ike_xchg_m_i_sig; break;
    }
  else
    switch (auth)
    {
    case x4c_ike_a1a_preshared: *xchg = x4v_ike_xchg_a_i_psk; break;
    case x4c_ike_a1a_rsa_sig:   *xchg = x4v_ike_xchg_a_i_sig; break;
    }

  x4_assert(xchg->et);

  /*  */
  xchg->modedata = s1;
  xchg->userdata = context;

  /*  */
  xchg->cipher = s1->sa.cipher;

  /*  */
  xchg->on_packet = s1->cb->ph1_send;
  xchg->on_resend = s1->cb->ph1_resend;
  xchg->on_crypto = s1->cb->ph1_sa_used;
}

/*
 *  phase 1 exchange templates
 */
#define HEADER(ET) (ET), btrue, 0, { 0 }, { 0 }, 0, 0, { 0 }

/* -- main mode, initiator side, preshared secret -- */
x4s_ike_exchange x4v_ike_xchg_m_i_psk =
  {
    HEADER(x4c_ike_et_main_mode),
    {
      x4_ike_m_send1, 
      x4_ike_m_send3, 
      x4_ike_m_send5_psk, 
      x4_ike_m_send7
    },
    {
      { x4_ike_m_recv2,     SA,         V | N },
      { x4_ike_m_recv4_psk, KE | NONCE, V | NATD },
      { x4_ike_m_recv6_psk, ID | HASH,  V | N }
    },
    _s1_xchg_on_advance
  };

/* -- main mode, initiator side, signatures -- */
x4s_ike_exchange x4v_ike_xchg_m_i_sig =
  {
    HEADER(x4c_ike_et_main_mode),
    {
      x4_ike_m_send1, 
      x4_ike_m_send3, 
      x4_ike_m_send5_sig,
      x4_ike_m_send7
    },
    {
      { x4_ike_m_recv2,     SA,         V | N },
      { x4_ike_m_recv4_sig, KE | NONCE, V | CR | NATD },
      { x4_ike_m_recv6_sig, ID | SIG,   V | CR | CERT | N }
    },
    _s1_xchg_on_advance
  };

/* -- aggressive mode, initiator side, preshared secret -- */
x4s_ike_exchange x4v_ike_xchg_a_i_psk =
  {
    HEADER(x4c_ike_et_aggressive_mode),
    {
      x4_ike_a_send1, 
      x4_ike_a_send3_psk
    },
    {
      { x4_ike_a_recv2_psk, SA | KE | NONCE | ID | HASH, V | NATD },
    },
    _s1_xchg_on_advance
  };

/* -- aggressive mode, initiator side, signatures -- */
x4s_ike_exchange x4v_ike_xchg_a_i_sig =
  {
    HEADER(x4c_ike_et_aggressive_mode),
    {
      x4_ike_a_send1, 
      x4_ike_a_send3_sig
    },
    {
      { x4_ike_a_recv2_sig, SA | KE | NONCE | ID | SIG, V | CR | CERT | NATD },
    },
    _s1_xchg_on_advance
  };
