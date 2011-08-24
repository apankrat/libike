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
 *	$Id: phase1_i_sig.c,v 1.8 2003/04/10 03:45:41 alex Exp $
 */

#include "phase1.h"
#include "utils.h"
#include "natt.h"

#include "x4/crypto/pki.h"
#include "x4/crypto/hmac.h"

/*
 *  -- local functions --
 */
static bval _process_cr(x4s_ike_phase1 * s1);
static bval _process_sig(x4s_ike_phase1 * s1, x4s_ike_payload * sig);
static bval _process_idr(x4s_ike_phase1 * s1);

static bval _append_cert(x4s_ike_phase1 * s1);
static bval _append_sig(x4s_ike_phase1 * s1);

static void _compute_skeyid_sig(x4s_ike_phase1 * s1);

/*
 *  main mode, 4th message, i < HDR, KE, Nr [, CR] [, NATD, NATD]
 */
bval x4_ike_m_recv4_sig(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * ke = m->by_type[x4c_ike_pt_ke],
                  * nr = m->by_type[x4c_ike_pt_nonce];

  /*  */
  x4_assert(xchg->seqno == 3);
  x4_assert(ke && nr);

  /* process NATD */
  if (! x4_natt_process_natd(s1))
    return x4_warn("m_recv4_sig: too few NATD payloads\n"), bfalse;

  /* copy what's needed */
  x4_buf_assignb(&s1->data.nr, &nr->body);
  x4_buf_assignb(&s1->data.ke.gy, &ke->body);

  /* process CR */
  if (! _process_cr(s1))
    return bfalse;

  /* compute DH secret, skeyidx and iv */
  if (! x4_dh_complete(&s1->data.ke))
    return x4_warn("a_recv2_sig: failed to compute DH secret\n"), bfalse;

  _compute_skeyid_sig(s1);

  x4_ike_compute1_skeyids(s1);

  x4_ike_compute1_enckey(s1);

  x4_ike_compute1_iv(s1);

  return btrue;
}

/*
 *  main mode, 5th message, i > HDR*, IDi, [CR,] [CERT,] SIG_I
 */
bval x4_ike_m_send5_sig(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 4);

  /*  */
  if (s1->natt)
    s1->cb->ph1_natt(xchg->userdata, 
                     x4_natt_float(s1->natt) ? &s1->link : 0, s1->nated);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);
 
  /* ID = local IP address */
  s1->data.idi = x4_ike_link_to_id(&s1->link, btrue);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s1->data.idi);

  /* CERT payload */
  if (! _append_cert(s1))
    return bfalse;

  /* CR payload (always send x.509 certreq) */
  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_cr, "\4", 1); 
  s1->data.cert_requested = btrue;

  /* SIG payload */
  if (! _append_sig(s1))
    return bfalse;

  /* send it out */
  return x4_ike_exchange_send(xchg,0);
}

/*
 *  main mode, 6th message, i < HDR*, IDr, [CERT,] SIG_R
 */
bval x4_ike_m_recv6_sig(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * id  = m->by_type[x4c_ike_pt_id];
  x4s_ike_payload * sig = m->by_type[x4c_ike_pt_sig];

  /*  */
  x4_assert(xchg->seqno == 5);
  x4_assert(id && sig);
  
  /* copy what's needed */
  x4_buf_assignb(&s1->data.idr, &id->body);

  /* verify signature */
  if (! _process_sig(s1, sig))
    return bfalse;

  /* process IDr payload */
  if (! _process_idr(s1))
    return bfalse;

  return btrue;
}

/*
 *  aggressive mode, 2nd message, 
 *  i < HDR, SA, KE, Nr, IDir, [CR,] [CERT,] [NATD, NATD,] SIG_R
 */
bval x4_ike_a_recv2_sig(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1  * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * sa = m->by_type[x4c_ike_pt_sa], 
                  * ke = m->by_type[x4c_ike_pt_ke], 
                  * nr = m->by_type[x4c_ike_pt_nonce], 
                  * id = m->by_type[x4c_ike_pt_id],
                  * sig = m->by_type[x4c_ike_pt_sig];

  /*  */
  x4_assert(xchg->seqno == 1);
  x4_assert(sa && ke && nr && id && sig);

  /* check that SA matches what we proposed */
  if (x4_ike_sa_compare(&sa->body, &s1->sa.raw, 0))
    return x4_warn("a_recv2_sig: different SA\n"), bfalse;

  /* copy what's needed */
  x4_memmove(s1->cr, m->hdr->cr, 8);
  x4_buf_assignb(&s1->data.idr, &id->body);
  x4_buf_assignb(&s1->data.nr, &nr->body);
  x4_buf_assignb(&s1->data.ke.gy, &ke->body);

  /* compute DH secret and SKEYID */
  if (! x4_dh_complete(&s1->data.ke))
    return x4_warn("a_recv2_psk: failed to compute DH secret\n"), bfalse;

  _compute_skeyid_sig(s1);

  /* process SIG and CERT (verify signature) */
  if (! _process_sig(s1, sig))
    return bfalse;

  /* process VID/NAT-T */
  x4_natt_process_vid(s1);

  /* process NATD */
  if (s1->natt)
    x4_natt_compute_hashes(s1);

  if (! x4_natt_process_natd(s1))
    return x4_warn("a_recv2_sig: unexpected/missing NATD payloads\n"), bfalse;

  /* process CR */
  if (! _process_cr(s1))
    return bfalse;

  /* process IDr */
  if (! _process_idr(s1))
    return bfalse;

  /* compute the rest of KEYMAT */
  x4_ike_compute1_skeyids(s1);

  x4_ike_compute1_enckey(s1);

  x4_ike_compute1_iv(s1);

  return btrue;
}

/*
 *  main mode, 3rd message, i >  HDR, [CERT,] [NAT-D, NAT-D,] SIG_I
 */
bval x4_ike_a_send3_sig(x4s_ike_exchange * xchg)
{
  x4s_ike_phase1 * s1 = (x4_assert(xchg && xchg->modedata), xchg->modedata);

  /*  */
  x4_assert(xchg->seqno == 2);

  /*  */
  if (s1->natt)
    s1->cb->ph1_natt(xchg->userdata, 
                     x4_natt_float(s1->natt) ? &s1->link : 0, s1->nated);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, 0);

  /* CERT payload */
  if (! _append_cert(s1))
    return bfalse;

  /* NATD payload */
  if (s1->natt)
    x4_natt_append_natd(s1);

  /* SIG payload */
  if (! _append_sig(s1))
    return bfalse;

  /* send it out */
  return x4_ike_exchange_send(xchg,0);
}

/*
 *  -- local methods --
 */
bval _process_cr(x4s_ike_phase1 * s1)
{
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_payload * cr = m->by_type[x4c_ike_pt_cr];

  if (! cr)
    return btrue;

  /*  */
  x4_buf_assignb(&s1->data.cr, &cr->body);

  if (! s1->cb->ph1_validate(s1->xchg.userdata, 
                             &s1->data.cr, 
                             x4c_ike_v1_cert_req))
  {
    x4_ike_exchange_die(&s1->xchg);
    return x4_error("m_recvx_sig: rejected cert request\n"), bfalse;
  }

  return btrue;
}

/*  */
bval _process_idr(x4s_ike_phase1 * s1)
{
  x4s_buf idr = { 0 };

  /*  */
  x4_assert(s1->data.idr.len);

  /*  */
  idr = x4_ike_link_to_id(&s1->link, bfalse);

  if (x4_buf_compare(&s1->data.idr, &idr))
    if (! s1->cb->ph1_validate(s1->xchg.userdata, &s1->data.idr, 
                               x4c_ike_v1_id))
    {
      x4_buf_free(&idr);
      x4_ike_exchange_die(&s1->xchg);
      return x4_logf(x4c_l_error, "m_recvx_sig: ID rejected\n"), bfalse;
    }

  x4_buf_free(&idr);
  return btrue;
}

/*  */
bval _process_sig(x4s_ike_phase1 * s1, x4s_ike_payload * sig)
{
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_payload * p;
 
  uint8 hv[x4c_hash_max];
  x4s_buf  hash = { 0 };
  x4s_buf  pkey = { 0 };

  /*  */
  x4_assert(sig);

  /* 
   *  first, try to obtain peer's public key from the certificate he sent
   */
  for (p=m->by_order; p->type; p++)
    if (p->type == x4c_ike_pt_cert)
    {
      if (p->body.data[0] == x4c_ike_ce_x509_sig)
        break;

      /* crl ? */
      x4_warn("m_recvx_sig: unsupported cert encoding (%u)\n", 
              x4m_uint8(p->body.data[0]));
    }

  if (p)
  {
    x4_buf_attach(&s1->data.cert, p->body.data+1, p->body.len-1);

    /* run the certificate by user */
    if (! s1->cb->ph1_validate(s1->xchg.userdata, 
                               &s1->data.cert, 
                               x4c_ike_v1_cert))
      return x4_warn("m_recvx_sig: peer's certificate rejected\n"), bfalse;

    /* get a key from the certificate */
    pkey = x4_get_rsa_pubkey(&s1->data.cert);
    if (! pkey.len)
      return x4_warn("m_recvx_sig: no rsa pubkey in certificate\n"), bfalse;
  }

  /* 
   *
   */
  if (s1->data.cert_requested)
    if (! pkey.len)
      x4_warn("m_recvx_sig: requested cert not received\n");

  /* 
   *  if no luck with cert. ask user for the pubkey, perhaps he knows 
   */
  if (! pkey.len)
    pkey = s1->cb->ph1_get_pubkey(s1->xchg.userdata, &s1->data.idr);

  if (! pkey.len)
    return x4_error("m_recv6_sig: no pubkey to verify signature\n"), bfalse;

  /*
   *  compute hash_r 
   */
  x4_ike_compute1_hashr(s1, hv);
  x4_buf_attach(&hash, hv, s1->sa.hasher->hlen);
           
  /*
   * verify signature
   */
  if (! x4_rsa_verify(&hash, &pkey, &sig->body))
  {
    x4_buf_free(&pkey);
    return x4_error("m_recv6_sig: failed to verify signature\n"), bfalse;
  }
  x4_buf_free(&pkey);

  return btrue;
}

/*  */
bval _append_cert(x4s_ike_phase1 * s1)
{
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);
  x4s_buf  cert = { 0 };

  /*  */
  cert = s1->cb->ph1_get_cert(xchg->userdata);
  if (! cert.len)
  {
    /* validate() on previous step must return bfalse */
    x4_assert(! s1->data.cr.len);

    return !s1->data.cr.len;
  }

  /* CERT */
  x4_buf_prepend(&cert, "\4", 1);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_cert, &cert);
  x4_buf_free(&cert);

  return btrue;
}

/*  */
bval _append_sig(x4s_ike_phase1 * s1)
{
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);
  x4s_buf  pkey = { 0 };
  x4s_buf  sigv = { 0 };
  uint8    hv[x4c_hash_max];
  x4s_buf  hash = { 0 };

  /* get private key */
  pkey = s1->cb->ph1_get_prikey(xchg->userdata);
  if (! pkey.len)
  {
    x4_assert(0);
    x4_logf(x4c_l_error, "m_sendx_sig: no private key to sign hash_i\n");
    return bfalse;
  }

  /* compute hash */
  x4_ike_compute1_hashi(s1, hv);
  x4_buf_attach(&hash, hv, s1->sa.hasher->hlen);

  /* sign */
  sigv = x4_rsa_sign(&hash, &pkey);
  if (! sigv.len)
  {
    x4_buf_free(&pkey);
    x4_logf(x4c_l_error, "m_sendx_sig: rsa_sign() failed\n");
    return bfalse;
  }

  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_sig, &sigv);
  
  x4_buf_free(&sigv);
  x4_buf_free(&pkey);

  return btrue;
}

/*  */
void _compute_skeyid_sig(x4s_ike_phase1 * s1)
{
  x4s_buf  key = { 0 };
  x4s_hasher * h;
  
  x4_assert(s1);

  /*  */
  x4_buf_assignb(&key, &s1->data.ni);
  x4_buf_appendb(&key, &s1->data.nr);

  /*  */
  h = x4_hmacb(s1->sa.hasher, &key);
  x4_buf_free(&key);
  x4_assert(h);

  x4_buf_resize(&s1->data.skeyid, 
              s1->sa.hasher->hlen);

  x4_hasher_updateb(h, &s1->data.ke.gxy);
  x4_hasher_completeb(h, &s1->data.skeyid);
}
