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
 *	$Id: phase1_i_psk.c,v 1.7 2003/04/10 03:45:41 alex Exp $
 */

#include "phase1.h"
#include "utils.h"
#include "natt.h"

#include "x4/crypto/hmac.h"

/* local functions */
static bval _process_hash(x4s_ike_phase1 * s1, x4s_ike_payload * hash);
static bval _process_idr (x4s_ike_phase1 * s1);

static bval _compute_skeyid_psk(x4s_ike_phase1 * s1);

/*
 *  main mode, 4th message, i < HDR, KE, Nr [, NAT-D, NAT-D]
 */
bval x4_ike_m_recv4_psk(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * ke = m->by_type[x4c_ike_pt_ke], 
                  * nr = m->by_type[x4c_ike_pt_nonce];

  /*  */
  x4_assert(xchg->seqno == 3);
  x4_assert(ke && nr);

  /* parse NATD payloads first */
  if (! x4_natt_process_natd(s1))
    return x4_warn("m_recv4_psk: problem with natd payload(s)\n"), bfalse;

  /* process NONCE and KE payloads */
  x4_buf_assignb(&s1->data.nr, &nr->body);
  x4_buf_assignb(&s1->data.ke.gy, &ke->body);

  /* compute DH secret, skeyidx and iv */
  if (! x4_dh_complete(&s1->data.ke))
    return x4_warn("m_recv4_psk: failed to compute DH secret\n"), bfalse;

  if (! _compute_skeyid_psk(s1))
  {
    x4_ike_exchange_die(xchg);
    return x4_warn("m_recv4_psk: failed to compute skeyid\n"), bfalse;
  }

  x4_ike_compute1_skeyids(s1);

  x4_ike_compute1_enckey(s1);

  x4_ike_compute1_iv(s1);

  return btrue;
}

/*
 *  main mode, 5th message, i > HDR*, IDii, HASH_I
 */
bval x4_ike_m_send5_psk(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  uint8 hv[x4c_hash_max];

  /*  */
  x4_assert(xchg->seqno == 4);

  /*  */
  if (s1->natt)
    s1->cb->ph1_natt(xchg->userdata, 
                     x4_natt_float(s1->natt) ? &s1->link : 0, s1->nated);

  /*  */
  s1->data.idi = x4_ike_link_to_id(&s1->link, btrue);

  /*  */
  x4_ike_compute1_hashi(s1, hv);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s1->data.idi);
  x4_ike_message_append (&xchg->out.pkt, x4c_ike_pt_hash, hv, 
                                         s1->sa.hasher->hlen);

  /* send it out */
  return x4_ike_exchange_send(xchg,0);
}

/*
 *  main mode, 6th message, i < HDR*, IDir, HASH_R
 */
bval x4_ike_m_recv6_psk(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * id = m->by_type[x4c_ike_pt_id],
                  * hash = m->by_type[x4c_ike_pt_hash];

  /*  */
  x4_assert(xchg->seqno == 5);
  x4_assert(id && hash);

  /*  */
  x4_buf_assignb(&s1->data.idr, &id->body);

  /* verify HASH */
  if (! _process_hash(s1, hash))
    return bfalse;

  /* process ID payload */
  if (! _process_idr(s1))
    return bfalse;

  return btrue;
}

/*
 *  aggressive mode, 2nd message, 
 *  i < HDR, SA, KE, Nr, IDir [,NAT-D, NAT-D], HASH_R
 */
bval x4_ike_a_recv2_psk(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * sa = m->by_type[x4c_ike_pt_sa], 
                  * ke = m->by_type[x4c_ike_pt_ke], 
                  * nr = m->by_type[x4c_ike_pt_nonce], 
                  * id = m->by_type[x4c_ike_pt_id], 
                  * hash = m->by_type[x4c_ike_pt_hash];

  /*  */
  x4_assert(xchg->seqno == 1);
  x4_assert(sa && ke && nr && id && hash);

  /* check that SA matches what we proposed */
  if (x4_ike_sa_compare(&sa->body, &s1->sa.raw, 0))
    return x4_warn("a_recv2_psk: different SA\n"), bfalse;

  /* copy what's needed */
  x4_memmove(s1->cr, m->hdr->cr, 8);
  x4_buf_assignb(&s1->data.idr, &id->body);
  x4_buf_assignb(&s1->data.nr, &nr->body);
  x4_buf_assignb(&s1->data.ke.gy, &ke->body);

  /* compute DH secret and SKEYID */
  if (! x4_dh_complete(&s1->data.ke))
    return x4_warn("a_recv2_psk: failed to compute DH secret\n"), bfalse;

  if (! _compute_skeyid_psk(s1))
  {
    x4_ike_exchange_die(xchg);
    return x4_warn("a_recv2_psk: failed to compute skeyid\n"), bfalse;
  }

  /* verify HASH */
  if (! _process_hash(s1, hash))
    return bfalse;

  /* check VID payloads for NAT-T capabilities */
  x4_natt_process_vid(s1);

  /* check for NATD payloads */
  if (s1->natt)
    x4_natt_compute_hashes(s1);

  if (! x4_natt_process_natd(s1))
    return x4_warn("a_recv2_psk: unexpected/missing NATD payloads\n"), bfalse;

  /* process ID payload */
  if (! _process_idr(s1))
    return bfalse;

  /* compute the rest of Phase 1 KEYMAT */
  x4_ike_compute1_skeyids(s1);

  x4_ike_compute1_enckey(s1);

  x4_ike_compute1_iv(s1);

  return btrue;  
}

/*
 *  aggressive mode, 3rd message, i > HDR*, [NAT-D, NAT-D,] HASH_I
 */
bval x4_ike_a_send3_psk(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  uint8 hv[x4c_hash_max];

  /*  */
  x4_assert(xchg->seqno == 2);

  /*  */
  if (s1->natt)
    s1->cb->ph1_natt(xchg->userdata, 
                     x4_natt_float(s1->natt) ? &s1->link : 0, s1->nated);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);

  if (s1->natt)
    x4_natt_append_natd(s1);

  x4_ike_compute1_hashi(s1, hv);
  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_hash, hv, 
                                        s1->sa.hasher->hlen);

  /* send it out */
  return x4_ike_exchange_send(xchg,0);
}

/*
 *  -- local method(s) --
 */
bval _process_hash(x4s_ike_phase1 * s1, x4s_ike_payload * hash)
{
  size_t    hlen;
  uint8     hv[x4c_hash_max];

  /*  */
  x4_assert(s1 && hash);

  /* verify HASH */
  hlen = s1->sa.hasher->hlen;

  if (hash->body.len != hlen)
    return x4_warn("m_recvx_psk: invalid hash len\n"), bfalse;

  x4_ike_compute1_hashr(s1, hv);

  if (x4_memcmp(hv, hash->body.data, hlen))
    return x4_logf(x4c_l_error, "m_recvx_psk: invalid hash_r\n"), bfalse;

  return btrue;
}

/*  */
bval _process_idr(x4s_ike_phase1 * s1)
{
  x4s_buf   idr = { 0 };

  /*  */
  x4_assert(s1);

  /*  */
  idr = x4_ike_link_to_id(&s1->link, bfalse);

  if (x4_buf_compare(&s1->data.idr, &idr))
    if (! s1->cb->ph1_validate(s1->xchg.userdata, &s1->data.idr, 
                               x4c_ike_v1_id))
    {
      x4_buf_free(&idr);
      x4_ike_exchange_die(&s1->xchg);
      return x4_logf(x4c_l_error, "m_recvx_psk: ID rejected\n"), bfalse;
    }

  x4_buf_free(&idr);

  return btrue;
}

/*  */
bval _compute_skeyid_psk(x4s_ike_phase1 * s1)
{
  x4s_buf psk = { 0 };
  x4s_hasher * h;
  size_t hlen;
  
  x4_assert(s1);

  /* query preshared secret */
  psk = s1->cb->ph1_get_psk(s1->xchg.userdata);
  if (! psk.len)
    return x4_logf(x4c_l_error, "m_recv4_psk: no preshared secret\n"), 
           bfalse;

  /*  */
  hlen = s1->sa.hasher->hlen;

  h = x4_hmacb(s1->sa.hasher, &psk);
  x4_buf_free(&psk);
  x4_assert(h);
 
  x4_buf_resize(&s1->data.skeyid, hlen);
  x4_hasher_updateb(h, &s1->data.ni);
  x4_hasher_updateb(h, &s1->data.nr);
  x4_hasher_completeb(h, &s1->data.skeyid);

  return btrue;
}
