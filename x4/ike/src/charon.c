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
 *	$Id: charon.c,v 1.4 2003/04/10 03:45:41 alex Exp $
 */

#include "phase1.h"
#include "phase2.h"
#include "phasex.h"
#include "utils.h"

#include "x4/ike/charon.h"
#include "x4/core/bswap.h"

/*
 *
 */
x4m_struct( x4s_ike )
{
  x4s_ike_config cfg;
  
  bval init;
  uint recursion;

  x4s_ike_phase1 * s1;
};

/* global variables */
static x4s_ike     _ike    = { 0 };
static const uint8 _ck0[8] = { 0 };

/* local functions */
static void _charon_enter();
static void _charon_leave();
static void _charon_purge();

static bval _charon_respond1(x4s_buf *);
static bval _charon_respond2(x4s_ike_phase1 *);

static void _charon_on_die1(x4s_ike_exchange *);
static void _charon_on_die2(x4s_ike_exchange *);

/*
 *  init / term
 */
void x4_charon_init(x4s_ike_config * cfg)
{
  x4_assert(cfg);
  x4_assert(! _ike.init);

  x4_assert(8 <= cfg->ph2_nlen && cfg->ph2_nlen <= 255);

  _ike.cfg = *cfg;
  _ike.init = btrue;
  _ike.recursion = 0;
}

/*  */
void x4_charon_term()
{
  x4s_ike_phase1 * s1;
  x4s_ike_phase2 * s2;

  x4_assert(_ike.init);
  x4_assert(! _ike.recursion);

  /* kill all exchanges .. */
  for (s1 = _ike.s1; s1; s1=s1->next)
  {
    if (s1->xchg.seqno)
      _charon_on_die1(&s1->xchg);

    for (s2 = s1->s2; s2; s2=s2->next)
      if (s2->xchg.seqno)
        _charon_on_die2(&s2->xchg);
  }

  /* .. and purge them */
  _charon_purge();
  
  _ike.init = bfalse;  
}

/*
 *  recv
 */
bval x4_charon_recv(const x4s_net_link * link, x4s_buf * pkt)
{
  x4s_isakmp_header * hdr;
  x4s_ike_phase1 * s1 = 0;
  x4s_ike_phase2 * s2 = 0;

  x4s_ike_exchange * xchg = 0;
  bval r;

  /*  */
  x4_assert(link && pkt);

  /*  */
  _charon_enter();

  /*  */
  if (pkt->len < 28)
    return x4_warn("packet: too small\n"), _charon_leave(), bfalse;

  /*  */
  hdr = (x4s_isakmp_header*)pkt->data;

  /* an initiator cookie must not be 0 */
  if (! x4_memcmp(hdr->ci, _ck0, 8))
    return x4_warn("header: cookie-i is zero\n"), _charon_leave(), bfalse;

  /* fetch phase 1 session */
  for (s1 = _ike.s1; s1; s1 = s1->next)
    if (! x4_memcmp(s1->ci, hdr->ci, 8))
      if (! x4_memcmp(s1->cr, hdr->cr, 8) ||
          s1->xchg.seqno == 1)
        break;
  
  /* unknown ph1 ike_exchange */
  if (! s1)
    return r = _charon_respond1(pkt), _charon_leave(), r;

  if (! s1->xchg.seqno)
    return x4_warn("charon_recv: expired ph1 ike_exchange\n"), 
           _charon_leave(), bfalse;

  /* verify it's coming from more-or-less valid address */
  if ( x4_net_compare_link(link, &s1->link, bfalse) )
    return x4_warn("charon_recv: invalid peer\n"), _charon_leave(), bfalse;

  xchg = &s1->xchg;

  /* find phase 2 session */
  if (hdr->msgid)
  {
    for (s2 = s1->s2; s2; s2 = s2->next)
      if (s2->msgid == hdr->msgid)
        break;

    if (s2)
      xchg = &s2->xchg;
  }

  /* check that exchange is not marked for disposal */
  if (! xchg->seqno)
    return _charon_leave(), bfalse;

  /* check if it's a retransmit */
  if (x4_ike_exchange_filter(xchg, pkt))
    return _charon_leave(), btrue;
  
  /* decrypt packet */
  if (hdr->flags & x4c_ike_hf_encryption)
  {
    if (! x4m_sa1_established(s1))
      return x4_warn("charon_recv: no sa for encrypted packet\n"), 
             _charon_leave(), bfalse;

    /*  */
    if (! s2 && hdr->msgid) 

      x4_ike_compute2_iv(hdr->msgid, s1, s1->xchg.in.iv);

    else

      x4_memmove(xchg->in.iv, xchg->iv, x4c_iv_max);

    if (! x4_ike_exchange_decrypt(xchg, pkt))
      return x4_warn("charon_recv: decryption failed\n"), 
             _charon_leave(), bfalse;
  }
  else
  {
    /* $hmm - shall we reject pkt if there is an ISAKMP SA in place ? */
    if (x4m_sa1_established(s1))
      x4_warn("charon_recv: plaintext packet\n");

    if (xchg->seqno == x4c_ike_state_completed)
      return _charon_leave(), bfalse;
  }
  
  /* unpack packet */
  if (! x4_ike_message_unpack(pkt, &xchg->in.msg, xchg->cipher->blen))
    return _charon_leave(), bfalse;

  /* demux */
  if (hdr->et == x4c_ike_et_informational)
    if (s2)
      return x4_warn("charon_recv: inf ike_exchange in ph2 context\n"), 
             _charon_leave(), bfalse;
    else
      return r = x4_ike_sx_recv_inf(s1), _charon_leave(), r;

  /* if a known ike_exchange */
  if (s2 || !hdr->msgid)
    return r = x4_ike_exchange_recv(xchg), _charon_leave(), r;

  if (hdr->et == x4c_ike_et_quick_mode)
    if (s1->xchg.seqno == x4c_ike_state_completed)

      return r = _charon_respond2(s1), _charon_leave(), r;

    else

      return x4_warn("charon_recv: qm ike_exchange in %u ph1 state\n",
                     x4m_uint8(s1->xchg.seqno)), 
             _charon_leave(), bfalse;

  return x4_warn("charon_recv: unhandled packet\n"), _charon_leave(), bfalse;
}

/*
 *  timed work
 */
void x4_charon_tick()
{
  x4s_ike_phase1 * s1;
  x4t_time tnow = x4_time();

  /*  */
  _charon_enter();

  /*
   * due to the implemented recursion control _ike.s1 and _ike.s1->s2 
   * lists will not have their items removed (indirectly through a
   * recursive calls to charon_xxx from the callbacks) while the loop 
   * below is executing. the lists may grow at the end though, which 
   * is fine as long as the correct loop exit condition is used.
   */
  for (s1 = _ike.s1; s1; s1 = s1->next)
  {
    x4s_ike_phase2 * s2;

    if (s1->xchg.seqno)
      x4_ike_exchange_tick(&s1->xchg, tnow);

    for (s2 = s1->s2; s2; s2 = s2->next)
      if (s2->xchg.seqno)
        x4_ike_exchange_tick(&s2->xchg, tnow);
  }

  /*  */
  _charon_leave();
}

/*
 *  initiate phase 1
 */
bval x4_charon_init1(const x4s_ike_config1 * s1c)
{
  x4s_ike_phase1 * s1 = 0;
  
  /* validate context */
  x4_assert(s1c);
  x4_assert(_ike.init);

  /*  */
  x4_assert(8 <= s1c->nlen && s1c->nlen <= 256);

  x4_assert(! _ike.recursion);  /* optional

  /*  */
  _charon_enter();

  /*  */
  s1 = x4_ike_i1_create(s1c, &_ike.cfg);
  x4_assert(s1);

  s1->cb = &_ike.cfg;
  s1->xchg.on_die = _charon_on_die1;

  /* insert into the list of managed sessions */
  s1->next = _ike.s1;
  _ike.s1 = s1;

  /* notify */
  _ike.cfg.ph1_initiated(s1->xchg.userdata, s1);

  /* send 1st packet out */
  if (! x4_ike_exchange_send_1st(&s1->xchg))
  {
    x4_assert(! s1->xchg.seqno);
    _charon_leave();
    return bfalse;
  }

  _charon_leave();
  return btrue;
}

/*
 *
 */
bval x4_charon_init2(const x4s_ike_config2 * s2c, x4s_ike_phase1 * s1)
{
  x4s_ike_phase1 * p1;
  x4s_ike_phase2 * s2;
  
  /*  */
  x4_assert(s1 && s2c);
  x4_assert(s1->xchg.seqno == x4c_ike_state_completed);

  /*  */
  _charon_enter();

  for (p1 = _ike.s1; p1; p1 = p1->next)
    if (p1 == s1)
      break;
  x4_assert(p1);

  /*  */
  s2 = x4_ike_i2_create(s2c, s1);
  x4_assert(s2);

  s2->xchg.on_die = _charon_on_die2;

  /* insert into the list of managed sessions */
  s2->next = s1->s2;
  s1->s2 = s2;

  /* notify */
  _ike.cfg.ph2_initiated(s2->xchg.userdata, s2);

  /*  */
  if (! x4_ike_exchange_send_1st(&s2->xchg))
  {
    x4_assert(! s2->xchg.seqno);
    _charon_leave();
    return bfalse;
  }

  _charon_leave();
  return btrue;
}

/*
 *
 */
void x4_charon_term1(x4s_ike_phase1 * s1)
{
  _charon_enter();
  _charon_on_die1(&s1->xchg);
  _charon_leave();
}

void x4_charon_term2(x4s_ike_phase2 * s2)
{
  _charon_enter();
  _charon_on_die2(&s2->xchg);
  _charon_leave();
}


/*
 *  local methods
 */
void _charon_enter()
{
  _ike.recursion++;
}

void _charon_leave()
{
  x4_assert(_ike.recursion);

  if (--_ike.recursion)
    return;

  /* purge dead exchanges */
  _charon_purge();
}

void _charon_purge()
{
  x4s_ike_phase1 ** p1;
  x4s_ike_phase2 ** p2;

  /*
   * sweep exchange lists and purge dead entries
   */ 
  for (p1 = &_ike.s1; *p1; )
  {
    /* phase2 */
    for (p2 = &(*p1)->s2; *p2; )
      if (! (*p2)->xchg.seqno)
      {
        x4s_ike_phase2 * s2 = *p2;

        *p2 = s2->next;
        x4_ike_phase2_free(s2);
        x4_free(s2);
      }
      else
        p2 = &(*p2)->next;

    /* phase 1 */
    if (! (*p1)->s2 && ! (*p1)->xchg.seqno)
    {
      x4s_ike_phase1 * s1 = *p1;

      *p1 = s1->next;
      x4_ike_phase1_free(s1);
      x4_free(s1);
    }
    else
      p1 = &(*p1)->next;
  }
}

/* phase 1 respond */
bval _charon_respond1(x4s_buf * pkt)
{
  x4s_isakmp_header * hdr = (x4s_isakmp_header *)(x4_assert(pkt), pkt->data);

  x4_assert(pkt->len >= 28);

  if (x4_memcmp(hdr->cr, _ck0, 8))
    return x4_warn("_charon_respond1: cr is not 0\n"), bfalse;

  if (hdr->msgid)
    return x4_warn("_charon_respond1: msgid is not 0\n"), bfalse;

  if (hdr->et != x4c_ike_et_main_mode || 
      hdr->et != x4c_ike_et_aggressive_mode)

    return x4_warn("_charon_respond1: invalid et (%u)\n", x4m_uint8(hdr->et)), 
           bfalse;

  x4_logf(x4c_l_info, "_charon_respond1: implement me\n");
  return bfalse;
}

/* phase 2 respond */
bval _charon_respond2(x4s_ike_phase1 * s1)
{
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_phase2 * s2;

  /*  */
  x4_assert(m->hdr->msgid && 
            m->hdr->et == x4c_ike_et_quick_mode);

  s2 = x4_ike_r2_create(s1);
  x4_assert(s2);

  s2->xchg.on_die = _charon_on_die2;

  s2->next = s1->s2;
  s1->s2 = s2;

  /* notify user */
  s2->xchg.userdata = _ike.cfg.ph2_responded(s1->xchg.userdata, s2);

  return x4_ike_exchange_recv(&s2->xchg);
}

/* mark phase 1 is dead */
void _charon_on_die1(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * p1;

  x4_assert(xchg->seqno != 0); /* cannot die twice */

  /* find it - sanity check */
  for (p1 = _ike.s1; p1 && (p1 != s1); p1 = p1->next);
  x4_assert(p1);

  /* send NOTIFY(DELETE) if some packets has alredy been sent out */
  if (xchg->seqno > 1)
    x4_ike_sx_send_delete(s1, 0);

  /* notify user */
  _ike.cfg.ph1_disposed(xchg->userdata);

  /* this dead exchange will be purged from the list by the 
     last call to _charon_leave() prior to leaving charon code 
     (at the top recursion level) */
}

/* mark phase 2 is dead */
void _charon_on_die2(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1, * p1;
  x4s_ike_phase2 * p2;

  x4_assert(s2->s1);
  x4_assert(xchg->seqno != 0); /* cannot die twice */

  s1 = s2->s1;

  /* find it - sanity check */
  for (p1 = _ike.s1; p1 && (p1 != s1); p1 = p1->next);
  x4_assert(p1);

  for (p2 = p1->s2; p2 && (p2 != s2); p2 = p2->next);
  x4_assert(p2);

  /* send NOTIFY(DELETE) if some packets has alredy been sent out */
  if (xchg->seqno > 1)
    x4_ike_sx_send_delete(s1, s2->sa.k.spi_l);

  /* notify user */
  _ike.cfg.ph2_disposed(s2->xchg.userdata);

  /* this dead exchange will be purged from the list by the 
     last call to _charon_leave() prior to leaving charon code 
     (at the top recursion level) */
}

