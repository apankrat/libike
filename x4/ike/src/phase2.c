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
 *	$Id: phase2.c,v 1.8 2003/04/27 21:37:37 alex Exp $
 */

#include "phase2.h"
#include "utils.h"
#include "natt.h"

#include "x4/core/bswap.h"
#include "x4/crypto/random.h"

/*
 *  -- local functions --
 */
static void  _s2_format_sa(x4s_ike_phase2 * s2, const x4s_ike_config2 * s2c);
static uint8 _s2_xchg_on_advance(x4s_ike_exchange * xchg);
static void  _s2_setup_exchange(x4s_ike_phase2 * , bval, void *);

extern x4s_ike_exchange x4v_ike_xchg_q_i;
extern x4s_ike_exchange x4v_ike_xchg_q_r;

/*
 *
 */
void x4_ike_phase2_free(x4s_ike_phase2 * s2)
{
  x4_assert(s2);

  /*  */
  x4_ike_exchange_free(&s2->xchg);

  x4_buf_free(&s2->data.ni);
  x4_buf_free(&s2->data.nr);

  x4_dh_data_free(&s2->data.ke);

  x4_buf_free(&s2->data.idi);
  x4_buf_free(&s2->data.idr);

  x4_buf_free(&s2->sa.k.key_l);
  x4_buf_free(&s2->sa.k.key_r);
  x4_buf_free(&s2->sa.raw);

  /* */
  x4_assert(! s2->next);
}

/*  */
x4s_ike_phase2 * x4_ike_i2_create(const x4s_ike_config2 * s2c,
                                  const x4s_ike_phase1 * s1)
{
  x4s_ike_phase2 * s2;
  
  /*  */
  x4_assert(s1 && s2c);
  x4_assert(8 <= s2c->nlen && s2c->nlen <= 256);

  x4_assert(! s2c->ipcomp); /* not yet */

  x4_assert(x4c_ike_a2e_tunnel <= s2c->encaps && 
            s2c->encaps <= x4c_ike_a2e_transport);

  /*  */
  s2 = (x4s_ike_phase2*)x4_mallocz(sizeof(x4s_ike_phase2));
  x4_assert(s2);

  /*  */
  s2->s1 = (void*)s1;                     /* casting removes const */

  /* generate Message ID */
  x4_random(&s2->msgid, 4);

  /* init SA params */
  s2->sa.k.spi_l  = s1->cb->ph2_get_spi();
  s2->sa.c = *s2c;

  /* generate nonce */
  x4_buf_resize(&s2->data.ni, s2c->nlen);
  x4_randomb(&s2->data.ni);

  /* assign DH params if PFS is selected */
  if (s2c->group)
  {
    s2->data.ke.p = x4_ike_select_prime(s2c->group);
    x4_assert(s2->data.ke.p.len);

    x4_buf_attach(&s2->data.ke.g, x4v_ike_modp_exp, 1);
  }

  /* setup x4s_ike_exchange */
  _s2_setup_exchange(s2, btrue, s2c->userdata);

  /* format s2->sa.raw */
  _s2_format_sa(s2, s2c);

  return s2;
}

/*  */
x4s_ike_phase2 * x4_ike_r2_create(const x4s_ike_phase1 * s1)
{
  x4s_ike_phase2 * s2;

  x4_assert(s1);

  /*  */
  s2 = (x4s_ike_phase2*)x4_mallocz(sizeof(x4s_ike_phase2));
  x4_assert(s2);

  /*  */
  s2->s1 = (void*)s1;                     /* casting removes const */
  s2->msgid = s1->xchg.in.msg.hdr->msgid;

  /* setup x4s_ike_exchange */
  _s2_setup_exchange(s2, bfalse, 0);

  /* copy s1->in to s2->in */
  x4_memmove(&s2->xchg.in, &s1->xchg.in, sizeof(x4s_ike_packet_in));

  return s2;
}

/*
 *
 */
void _s2_format_sa(x4s_ike_phase2 * s2, const x4s_ike_config2 * s2c)
{
  x4s_ike_sa_payload     sa = { 0 };
  x4s_ike_sa_proposal  * pr = sa.pr;
  x4s_ike_sa_transform * tr;
  x4s_ike_sa_attribute * a;

  /*  */
  x4_assert(s2 && s2c);

  /*  */
  sa.doi = x4c_ike_doi_ipsec;
  sa.sit = x4c_ike_sit_identity_only;

  /* -- ipcomp --
  if (s2c->ipcomp)
  {
    pr->index = 1;
    pr->proto = proto_ipsec_ipcomp;
    x4_buf_attach(&pr->spi, &s2->sa.spi_l, 4); /* $hmm - ?!! *

    tr = pr->tr;
    tr->index = 1;
    tr->type  = s2c->ipcomp;

    a = tr->attr;
    a->type = p2a_encapsulation_mode;
    a->val  = s2c->encaps;
    a++;

    if (s2c->group)
    {
      a->type = p1a_group_description;
      a->val  = s2c->group;
      a++;
    }

    /*
        According to www.sandelman.ottawa.on.ca/ipsec/2000/12/msg00040.html
        encapsulation IPCOMP and ESP modes must be the same.
     *
    pr++;
  }
  */

  /* -- esp -- */
  pr->index = 1;
  pr->proto = x4c_ike_proto_ipsec_esp;
  x4_buf_attach(&pr->spi, &s2->sa.k.spi_l, 4);

  tr = pr->tr;
  tr->index = 1;
  tr->type  = s2c->cipher;
  
  a = tr->attr;
  a->type = x4c_ike_a2_encapsulation_mode;
  a->val  = x4_natt_encaps( s2->s1->natt, s2c->encaps );
  a++;

  if (s2c->auth)
  {
    a->type = x4c_ike_a2_auth_algorithm;
    a->val  = s2c->auth;
    a++;
  }

  if (s2c->cipher == x4c_ike_tr_esp_aes)
  {
    a->type = x4c_ike_a2_key_length;
    a->val  = s2c->kbits;
    a++;
  }

  if (s2c->group)
  {
    a->type = x4c_ike_a2_oakley_group;
    a->val  = s2c->group;
    a++;
  }

  if (s2c->lifetime.seconds)
  {
    a->type = x4c_ike_a2_life_type;
    a->val  = x4c_ike_a1l_seconds;
    a++;
    a->type = x4c_ike_a2_life_duration;
    a->val  = s2c->lifetime.seconds;
    a++;
  }

  if (s2c->lifetime.kbytes)
  {
    a->type = x4c_ike_a2_life_type;
    a->val  = x4c_ike_a1l_kilobytes;
    a++;
    a->type = x4c_ike_a2_life_duration;
    a->val  = s2c->lifetime.kbytes;
    a++;
  }

  x4_ike_sa_pack(&sa, &s2->sa.raw);
}

/*  */
uint8 _s2_xchg_on_advance(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);
  uint seqno = xchg->seqno;

  x4_assert(xchg->seqno < 4);

  xchg->seqno++;
  if (xchg->seqno == 3 && !s2->data.commit ||
      xchg->seqno == 4)
  {
    xchg->seqno = x4c_ike_state_completed;
  }

  if (xchg->seqno == x4c_ike_state_completed)
    s1->cb->ph2_completed(xchg->userdata, &s2->sa.k);

  return xchg->seqno;
}

/*  */
void _s2_setup_exchange(x4s_ike_phase2 * s2, bval init, void * context)
{
  /*  */
  x4s_ike_exchange * xchg = (x4_assert(s2), &s2->xchg);
  
  x4_assert(s2->s1);

  /*  */
  *xchg = init ? x4v_ike_xchg_q_i : 
                 x4v_ike_xchg_q_r;

  xchg->initiator = init;

  /*  */
  xchg->modedata = s2;
  xchg->userdata = context;

  /*  */
  xchg->cipher = s2->s1->sa.cipher;
  xchg->key    = s2->s1->sa.key;

  /*  */
  xchg->on_packet  = s2->s1->cb->ph2_send;
  xchg->on_resend  = s2->s1->cb->ph2_resend;
  xchg->on_crypto  = s2->s1->cb->ph1_sa_used;

  /*  */
  x4_ike_compute2_iv(s2->msgid, s2->s1, xchg->iv);
}

/*
 *  phase 2 exchange templates
 */
#define HEADER(ET) (ET), btrue, 0, { 0 }, { 0 }, 0, 0, { 0 }

/* -- quick mode, initiator side -- */
x4s_ike_exchange x4v_ike_xchg_q_i =
  {
    HEADER(x4c_ike_et_quick_mode),
    {
      x4_ike_q_send1, 
      x4_ike_q_send3,
    },
    {
      { x4_ike_q_recv2, HASH | SA | NONCE, KE | ID | N | NATOA },
      { x4_ike_q_recv4, HASH | N, 0 },
    },
    _s2_xchg_on_advance
  };

/* -- quick mode, responder side -- */
x4s_ike_exchange x4v_ike_xchg_q_r =
  {
    HEADER(x4c_ike_et_quick_mode),
    {
      x4_ike_q_send2, 
      x4_ike_q_send4,
    },
    {
      { x4_ike_q_recv1, HASH | SA | NONCE, SA | KE | ID | N | NATOA },
      { x4_ike_q_recv3, HASH, 0 },
    },
    _s2_xchg_on_advance
  };
