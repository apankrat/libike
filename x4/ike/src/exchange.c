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
 *	$Id: exchange.c,v 1.5 2003/04/27 21:37:37 alex Exp $
 */

#include "exchange.h"

#include "x4/core/bswap.h"

/*
 *  -- locals --
 */
static void _exchange_encrypt(x4s_ike_exchange * xchg, uint8 * iv);
static void _exchange_resend(x4s_ike_exchange * xchg, bval dejavu);
static uint _exchange_resend_default(void *, uint , uint , bval );

/*
 *
 */
void x4_ike_exchange_free(x4s_ike_exchange * xchg)
{
  x4_assert(xchg);

  x4_ike_packet_in_free(&xchg->in);
  x4_ike_packet_out_free(&xchg->out);
}

/*
 *
 */
bval x4_ike_exchange_filter(x4s_ike_exchange * xchg, x4s_buf * pkt)
{
  x4_assert(xchg && pkt);

  x4_hasher_processb(x4v_md5, pkt, xchg->in.hash);

  if (x4_memcmp(xchg->out.hash, xchg->in.hash, 16))
    return bfalse;

  /* -- it's a retransmit -- */
  x4_info("xchg_filter: inbound retransmit\n");

  _exchange_resend(xchg, btrue);

  return btrue;
}

/*
 *
 */
bval x4_ike_exchange_decrypt(x4s_ike_exchange * xchg, x4s_buf * pkt)
{
  size_t plen, blen;

  x4_assert(xchg && pkt);
  x4_assert(xchg->key && xchg->cipher);

  /* -- check length -- */
  plen = pkt->len;
  if (plen < 28)
    return x4_warn("xchg_decrypt: packet is too small\n"), bfalse;

  blen = xchg->cipher->blen;
  plen-= 28;
  if (plen % blen)
    return x4_warn("xchg_decrypt: uneven packet len\n"), bfalse;

  /* -- decrypt -- */
  xchg->cipher->decrypt(xchg->key, 
                        xchg->in.iv,
                        pkt->data+28, 
                        pkt->data+28,
                        plen / blen);

  /* -- notify -- */
  xchg->on_crypto(xchg->userdata, plen);

  return btrue;
}

/*
 *
 */
bval x4_ike_exchange_recv(x4s_ike_exchange * xchg)
{
  x4s_ike_message * m;
  uint  step;
  uint  req, opt;

  x4_assert(xchg);

  m = &xchg->in.msg;

  x4_assert(xchg->et == x4c_ike_et_main_mode && ! m->hdr->msgid ||
            xchg->et == x4c_ike_et_aggressive_mode && ! m->hdr->msgid ||
            xchg->et == x4c_ike_et_quick_mode && m->hdr->msgid);

  /* -- check mode -- */
  if (m->hdr->et != xchg->et)
    return x4_warn("xchg_recv: %u msg for %u xchg in %u state\n",
                   x4m_uint8(m->hdr->et), x4m_uint8(xchg->et), 
                   x4m_uint8(xchg->seqno)), bfalse;

  /* -- check state -- */
  if (xchg->seqno == x4c_ike_state_completed)
    return x4_warn("xchg_recv: x4s_ike_exchange is already completed\n"),
                   bfalse;

  step = xchg->seqno >> 1;

  /* -- check payloads -- */
  req = xchg->on_recv[step].required;
  opt = xchg->on_recv[step].optional;

  if ( req != (m->mask_t & req) ||
       0   != (m->mask_t & ~(req | opt)) ||
       0   != (m->mask_r & ~opt) )
    
    return x4_warn("xchg_recv: wrong payloads %x:%x in %u of %u\n", 
                   m->mask_t, m->mask_r, xchg->seqno, xchg->et),
                   bfalse;

  /* -- receive -- */
  x4_assert(xchg->on_recv[step].h);
  if (! xchg->on_recv[step].h(xchg))
    return bfalse;

  /* -- update IV -- */
  if (m->hdr->flags & x4c_ike_hf_encryption)
    x4_memmove(xchg->iv, xchg->in.iv, x4c_iv_max);

  /* -- update outbound packet info -- */
  x4_ike_packet_out_reset(&xchg->out, xchg->in.hash);

  /* -- advance the state -- */
  if (xchg->on_advance(xchg) == x4c_ike_state_completed)
    return btrue;

  /* -- respond -- */
  step = xchg->seqno >> 1;

  x4_assert(xchg->on_send[step]);
  if (! xchg->on_send[step](xchg))
    return x4_ike_exchange_die(xchg), bfalse;

  /* -- advance the state -- */
  xchg->on_advance(xchg);

  return btrue;
}

/*
 *
 */
bval x4_ike_exchange_send_1st(x4s_ike_exchange * xchg)
{
  x4_assert(xchg && xchg->seqno == 0);

  /* -- send the 1st packet out -- */
  x4_assert(xchg->on_send[0]);
  if (! xchg->on_send[0](xchg))
  {
    xchg->seqno++;      /* on_die() expects seqno to be non-zero */
    x4_ike_exchange_die(xchg);
    return bfalse;
  }

  /* -- advance the state -- */
  xchg->on_advance(xchg);

  return btrue;
}

/*
 *
 */
bval x4_ike_exchange_send(x4s_ike_exchange * xchg, uint8 * iv)
{
  x4_assert(xchg && xchg->cipher);

  /* encrypt if can */
  if (xchg->key)
    _exchange_encrypt(xchg, iv);

  /* send out */
  x4_assert(xchg->on_packet);
  if (! xchg->on_packet(xchg->userdata, &xchg->out.pkt))
    return x4_error("xchg_send: failed\n"), bfalse;

  /* init schedule */
  xchg->out.timestamp = x4_time();
  xchg->out.timeout   = 1;
  xchg->out.retry     = 1;
   
  return btrue;
}

/*
 *
 */
bval x4_ike_exchange_tick(x4s_ike_exchange * xchg, x4t_time tnow)
{
  x4_assert(xchg);
  x4_assert(xchg->seqno);   /* the caller must've checked this */

  if (xchg->out.timeout &&
      xchg->out.timestamp + xchg->out.timeout < tnow)

    _exchange_resend(xchg, bfalse);

  return btrue;
}

/*
 *
 */
void x4_ike_exchange_die(x4s_ike_exchange * xchg)
{
  x4_assert(xchg);

  if (! xchg->seqno)        
  {
    x4_assert(0);           /* should not die twice */
    return;
  }

  x4_assert(xchg->on_die);
  xchg->on_die(xchg);

  x4_assert(xchg->seqno);   /* must not get changed in the callback */
  xchg->seqno = 0;
}

/*
 *  -- local methods --
 */
void _exchange_encrypt(x4s_ike_exchange * xchg, uint8 * iv)
{
  x4s_buf           * pkt = (x4_assert(xchg), &xchg->out.pkt);
  x4s_isakmp_header * hdr = (x4s_isakmp_header*)pkt->data;
  size_t blen, plen, dlen;

  x4_assert(xchg->key && xchg->cipher);
  x4_assert(pkt->len > 28);

  /*  */
  hdr->flags |= x4c_ike_hf_encryption;

  /*  */
  dlen = pkt->len - 28;
  blen = xchg->cipher->blen;
  plen = (blen - dlen % blen) % blen;
  if (plen)
  {
    hdr->len = x4_bswap32(plen + x4_bswap32(hdr->len));
    dlen += plen;
    x4_buf_append(pkt, 0, plen);
  }

  /* encrypt */
  xchg->cipher->encrypt(xchg->key, 
                        iv ? iv : xchg->iv,
                        pkt->data + 28,
                        pkt->data + 28,
                        dlen / blen);

  /* notify */
  xchg->on_crypto(xchg->userdata, dlen);
}

/*
 *
 */
void _exchange_resend(x4s_ike_exchange * xchg, bval dejavu)
{
  uint (* decide)(void * , uint , uint , bval );
  
  /*  */
  x4_assert(xchg);

  /* determine the next pause */
  decide = xchg->on_resend ? xchg->on_resend : _exchange_resend_default;

  xchg->out.timeout = decide(xchg->userdata, xchg->seqno, 
                             xchg->out.retry, dejavu);

  if (! xchg->out.timeout)
  {
    /* this signals the end for incomplete exchanges */
    if (xchg->seqno != x4c_ike_state_completed)
      x4_ike_exchange_die(xchg);

    /* .. otherwise it just stops packet retransmissions */
    return;
  }

  x4_assert(xchg->on_packet);
  if (! xchg->on_packet(xchg->userdata, &xchg->out.pkt))
  {
    x4_error("xchg_resend: failed\n");
    x4_ike_exchange_die(xchg);
    return;
  }

  /* update schedule */
  xchg->out.timestamp = x4_time();
  xchg->out.retry++;
}

/*
 *
 */
uint _exchange_resend_default(void * c, uint seqno, uint retry, bval dejavu)
{
  /*
   *  For incomplete exchanges - 
   *    retransmit packet 3 times 2 seconds apart
   *
   *  For complete exchanges - 
   *    retransmit only in response to peer's retransmissions
   *
   */

  if (seqno != x4c_ike_state_completed)
    return retry < 3 ? 2 : 0;

  return dejavu ? 1 : 0;
}
