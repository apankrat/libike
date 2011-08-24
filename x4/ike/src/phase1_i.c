/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: phase1_i.c,v 1.8 2003/04/10 03:51:00 alex Exp $
 */

#include "phase1.h"
#include "phasex.h"
#include "utils.h"
#include "natt.h"

#include "x4/core/bswap.h"

/*
 *  main mode, 1st message, i > HDR, SA [, VID]
 */
bval x4_ike_m_send1(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 0);

  /*  */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_sa, &s1->sa.raw);
  
  /*  */
  x4_natt_append_vid(s1);

  return x4_ike_exchange_send(xchg,0);
}

/*
 *  main mode, 2nd message, i < HDR, SA [, VID]
 */
bval x4_ike_m_recv2(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  x4s_ike_message * m = (x4_assert(xchg), &xchg->in.msg);
  x4s_ike_payload * sa = m->by_type[x4c_ike_pt_sa];

  /*  */
  x4_assert(xchg->seqno == 1);
  x4_assert(sa);

  /* rfc 2409, section 5 */
  if (m->by_order[0].type != x4c_ike_pt_sa)
    return x4_warn("m_recv2: 1st payload is not SA\n"), bfalse;

  /* check that SA matches what we proposed */
  if (x4_ike_sa_compare(&sa->body, &s1->sa.raw, 0))
    return x4_warn("m_recv2: different SA\n"), bfalse;

  /* remember R cookie */
  x4_memmove(s1->cr, m->hdr->cr, 8);

  /* adjust s1->natt according to peer's NAT-T capabilities */
  x4_natt_process_vid(s1);

  return btrue;
}

/*
 *  main mode, 3rd message, i > HDR, KE, Ni [, NATD, NATD]
 */
bval x4_ike_m_send3(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 2);

  /* generate private DH key */
  x4_dh_initiate(&s1->data.ke);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_ke, &s1->data.ke.gx);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_nonce, &s1->data.ni);

  if (s1->natt)
  {
    x4_natt_compute_hashes(s1);
    x4_natt_append_natd(s1);
  }

  return x4_ike_exchange_send(xchg,0);
}

/*
 *  main mode, 7th message, i > HDR*, N(INITIAL_CONTACT)
 */
bval x4_ike_m_send7(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 6);

  return x4_ike_sx_send_inf(s1, x4c_ike_nms_initial_contact, 0);
}

/*
 *  aggressive mode, 1st message, i > HDR, SA, KE, Ni, IDii [, VID]
 */
bval x4_ike_a_send1(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 0);

  /* generate private DH key */
  x4_dh_initiate(&s1->data.ke);

  /* format ID payload */
  s1->data.idi = x4_ike_link_to_id(&s1->link, btrue);

  /*  */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_sa, &s1->sa.raw);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_ke, &s1->data.ke.gx);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_nonce, &s1->data.ni);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s1->data.idi);
  
  /*  append NAT-T capabilities */
  x4_natt_append_vid(s1);

  return x4_ike_exchange_send(xchg,0);
}
