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
 *	$Id: phase2_i.c,v 1.6 2003/04/10 03:45:41 alex Exp $
 */

#include "phase2.h"
#include "phasex.h"
#include "utils.h"

#include "x4/core/bswap.h"

/*
 *  initiator
 */
bval x4_ike_q_send1(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);
  x4s_net_selector * sel = &s2->sa.c.selector;

  /* i > HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] [, NAT-OAi, NAT-OAr] */
  x4_assert(xchg->seqno == 0);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, s2->msgid);
  x4_ike_message_append (&xchg->out.pkt, x4c_ike_pt_hash,
                         0, s1->sa.hasher->hlen);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_sa, &s2->sa.raw);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_nonce, &s2->data.ni);
  
  /* KE if needed */
  if (s2->data.ke.g.len)
  {
    x4_dh_initiate(&s2->data.ke);
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_ke, &s2->data.ke.gx);
  }

  /*
   *  Send IDci and IDcr if explicitely requested by the user 
   *  (s1->cb->send_ids is non-zero) or the selector is not a 
   *  simple us-to-peer selector
   */    
  if (s1->cb->send_ids ||
      ! x4_net_is_empty_selector(sel) &&
      ! x4_net_is_ip2ip_selector(sel, &s1->link) )
  {

    if (x4_net_is_empty_selector(sel))
    {
      s2->data.idi = x4_ike_link_to_id(&s2->s1->link, btrue);
      s2->data.idr = x4_ike_link_to_id(&s2->s1->link, bfalse);
    }
    else
    {
      s2->data.idi = x4_ike_selector_to_id(sel, btrue);
      s2->data.idr = x4_ike_selector_to_id(sel, bfalse);
    }

    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s2->data.idi);
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s2->data.idr);
  }

  /* hash the packet */
  x4_ike_compute2_hash1(s2->msgid, s1, &xchg->out.pkt, xchg->out.pkt.data+28+4);

  return x4_ike_exchange_send(xchg,0);
}

/*  */
bval x4_ike_q_recv2(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /*  
   *  i < HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] [, NAT-OAi, NAT-OAr]
   *
   *  $note: NAT-OA payloads are currently ignored
   */
  x4s_ike_message  * m = &xchg->in.msg;
  x4s_ike_payload  * hash;
  uint8  hv [x4c_hash_max];

  /*  */
  x4_assert(xchg->seqno == 1);

/*
    if (m->mask_t & PT_N)
    {
      m->hdr->flags &= ~x4c_ike_hf_encryption;
      m->mask_t = PT_N;
      m->mask_r = 0;
      x4_ike_sx_recv_inf(s1, m);
    }
*/

  if (m->by_order[0].type != x4c_ike_pt_hash || 
      m->by_order[1].type != x4c_ike_pt_sa)
    return x4_warn("q_recv2: invalid payload order\n"), bfalse;

  if ( !s2->data.ke.g.len != !(m->mask_t & KE) )
    return x4_warn("q_recv2: unexpected or missing KE payload\n"), bfalse;

  /* validate hash */
  hash = m->by_type[x4c_ike_pt_hash];
  if (hash->body.len != s1->sa.hasher->hlen)
    return x4_warn("q_recv2: invalid hash len\n"), bfalse;

  x4_ike_compute2_hash2(s2, &m->pkt, hv);

  if (x4_memcmp(hv, hash->body.data, hash->body.len))
    return x4_warn("q_recv2: invalid hash\n"), bfalse;

  /* validate returned IDs */
  if (m->mask_t & ID)
  {
    x4s_ike_payload * id = m->by_type[x4c_ike_pt_id];

    if (x4_buf_compare(&id->body, &s2->data.idi))
    {
      x4_ike_exchange_die(xchg);
      return x4_warn("q_recv2: mismatching IDi payload\n"), bfalse;
    }

    if ((++id)->type != x4c_ike_pt_id)
    {
      x4_ike_exchange_die(xchg);
      return x4_warn("q_recv2: missing IDr payload\n"), bfalse;
    }

    if (x4_buf_compare(&id->body, &s2->data.idr))
    {
      x4_ike_exchange_die(xchg);
      return x4_warn("q_recv2: mismatching IDr payload\n"), bfalse;
    }
  }

  /* validate SA and fetch peer's SPI at the same time */
  if (x4_ike_sa_compare(&s2->sa.raw, 
                        &m->by_type[x4c_ike_pt_sa]->body, 
                        &s2->sa.k.spi_r))
  {
    x4_ike_exchange_die(xchg);
    return x4_warn("q_recv2: mismatching SA payload\n"), bfalse;
  }

  /*  */
  if (m->hdr->flags & x4c_ike_hf_commit)
    s2->data.commit = btrue;  
  
  /*  */
  x4_buf_assignb(&s2->data.nr, &m->by_type[x4c_ike_pt_nonce]->body);
  
  /*  */
  if (m->mask_t & KE)
  {
    x4s_ike_payload * ke = m->by_type[x4c_ike_pt_ke];

    x4_buf_assignb(&s2->data.ke.gy, &ke->body);

    /* compute DH secret, skeyidx and iv */
    if (! x4_dh_complete(&s2->data.ke))
    {
      x4_ike_exchange_die(xchg);
      return x4_warn("q_recv2: failed to compute DH secret\n"), bfalse;
    }      
  }

  /* compute keymat */
  x4_ike_compute2_keymat(s2);

  return btrue;
}

/*  */
bval x4_ike_q_send3(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /* i > HDR*, HASH(3)  */
  uint8  hv[x4c_hash_max];
  
  x4_assert(xchg->seqno == 2);

  /* compute hash */
  x4_ike_compute2_hash3(s2, hv);

  /* format message */
  x4_ike_message_create(&xchg->out.pkt, s1->ci, s1->cr, xchg->et, s2->msgid);
  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_hash, 
                        hv, s1->sa.hasher->hlen);
            
  return x4_ike_exchange_send(xchg,0);
}

/*  */
bval x4_ike_q_recv4(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /* i > HDR*, HASH, N */
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * hash;
  uint8 hv [x4c_hash_max];
  
  x4s_ike_payload * notify;
  x4s_isakmp_notify * ip;

  /*  */
  x4_assert(xchg->seqno == 3);
  x4_assert(s2->data.commit);

  /* verify hash */
  hash = m->by_type[x4c_ike_pt_hash];

  if (hash->body.len != s1->sa.hasher->hlen)
    return x4_warn("q_recv4: invalid hash len\n"), bfalse;

  x4_ike_compute2_hash1(m->hdr->msgid, s1, &m->pkt, hv);

  if (x4_memcmp(hash->body.data, hv, hash->body.len))
    return x4_warn("q_recv4: invalid hash\n"), bfalse;

  /* check it's CONNECTED notify */
  notify = m->by_type[x4c_ike_pt_n];
  if (! x4_ike_sx_check_notify(&notify->body, 4))
    return bfalse;

  ip = (x4s_isakmp_notify*)(notify->body.data);
  if (ip->type != x4_bswap16(x4c_ike_nms_connected))
    return x4_warn("q_recv4: notify is not 'CONNECTED'\n"), bfalse;

  if (*(uint32*)(ip+1) != s2->sa.k.spi_r)
    return x4_warn("q_recv4: wrong spi\n"), bfalse;

  return btrue;
}
