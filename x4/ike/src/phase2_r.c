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
 *	$Id: phase2_r.c,v 1.6 2003/04/10 03:45:41 alex Exp $
 */

#include "phase2.h"
#include "phasex.h"
#include "utils.h"

#include "x4/core/bswap.h"
#include "x4/crypto/random.h"

/* local functions */
static bval _s2r_process_sa(x4s_ike_phase2 *);

/*
 *  responder
 */
bval x4_ike_q_recv1(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /* r < HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] */
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * hash;
  uint8 hv [x4c_hash_max];

  /*  */
  x4_assert(xchg->seqno == 0);

  /* validate  */
  if (m->by_order[0].type != x4c_ike_pt_hash || 
      m->by_order[1].type != x4c_ike_pt_sa)
    return x4_warn("q_recv1: invalid payload order\n"), bfalse;

  /* validate hash */
  hash = m->by_type[x4c_ike_pt_hash];
  if (hash->body.len != s1->sa.hasher->hlen)
    return x4_warn("q_recv1: invalid hash len\n"), bfalse;

  x4_ike_compute2_hash2(s2, &m->pkt, hv);

  if (x4_memcmp(hv, hash->body.data, hash->body.len))
    return x4_warn("q_recv1: invalid hash\n"), bfalse;

  /* parse and check SA */
  if (m->mask_r & SA)
    x4_warn("q_recv1: multiple SAs, all but first are ignored\n");

  x4_buf_assignb(&s2->sa.raw, &m->by_type[x4c_ike_pt_sa]->body);

  if (! _s2r_process_sa(s2))
    return bfalse;

  /* process Ni payload */
  x4_buf_assignb(&s2->data.ni, &m->by_type[x4c_ike_pt_nonce]->body);

  /* process ID payloads */
  if (m->mask_t & ID)
  {
    x4s_ike_payload * id = m->by_type[x4c_ike_pt_id];

    if (! x4_ike_id_to_selector(&id->body, &s2->sa.c.selector, bfalse))
      return x4_warn("q_recv1: invalid IDi payload\n"), bfalse;

    if ((++id)->type != x4c_ike_pt_id)
      return x4_warn("q_recv1: missing IDr payload\n"), bfalse;

    if (! x4_ike_id_to_selector(&id->body, &s2->sa.c.selector, btrue))
      return x4_warn("q_recv1: invalid IDi payload\n"), bfalse;

  }
  else
  {
    x4_net_ip2ip_to_selector(&s1->link, &s2->sa.c.selector);
  }

  /* run by user */
  if (! s2->s1->cb->ph2_validate(xchg->userdata, &s2->sa.c))
    return x4_warn("q_recv1: SA rejected\n"), bfalse;

  /* generate local spi */
  s2->sa.k.spi_l = s2->s1->cb->ph2_get_spi();

  /*  */
  s2->sa.c.nlen = s2->s1->cb->ph2_nlen;

  if (m->hdr->flags & x4c_ike_hf_commit)
    s2->data.commit = btrue;

  /* process KE payload */
  if (s2->sa.c.group)
  {
    s2->data.ke.p = x4_ike_select_prime(s2->sa.c.group);
    if (! s2->data.ke.p.len)
      return x4_warn("q_recv1: unsupported DH group\n"), bfalse;

    x4_buf_attach(&s2->data.ke.g, x4v_ike_modp_exp, 1);
    x4_buf_attachb(&s2->data.ke.gy, &m->by_type[x4c_ike_pt_ke]->body);

    x4_dh_initiate(&s2->data.ke);
    /* postpone expensive compute_ke_secret() call until recv3() */
  }

  /* generate nonce */
  x4_buf_resize(&s2->data.nr, s2->sa.c.nlen);
  x4_randomb(&s2->data.nr);

  /* generate SA */
  {
    x4s_ike_sa_payload sa;
    x4_ike_sa_unpack(&s2->sa.raw, &sa);

    x4_buf_attach(&sa.pr[0].spi, &s2->sa.k.spi_l, 4);
    sa.pr[0].tr[1].index = 0; /* truncate */
    sa.pr[1].index = 0;       /* truncate */

    x4_ike_sa_pack(&sa, &s2->sa.raw);
  }

  return btrue;
}

bval x4_ike_q_send2(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);
  x4s_net_selector * sel = &s2->sa.c.selector;

  /* r > HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] */
  x4_assert(xchg->seqno == 1);

  /* format message */
  x4_ike_message_create (&xchg->out.pkt, s1->ci, s1->cr, xchg->et, s2->msgid);
  x4_ike_message_append (&xchg->out.pkt, x4c_ike_pt_hash, 
                         0, s1->sa.hasher->hlen);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_sa, &s2->sa.raw);
  x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_nonce, &s2->data.nr);
  
  /* KE if needed */
  if (s2->data.ke.g.len)
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_ke, &s2->data.ke.gx);

  /* IDci, IDcr if needed */
  if (s1->cb->send_ids ||
      ! x4_net_is_ip2ip_selector(sel, &s1->link) )
  {
    x4_assert( !x4_net_is_empty_selector(sel) );  /* init'ed by r2_recv1 */

    s2->data.idi = x4_ike_selector_to_id(sel, btrue);
    s2->data.idr = x4_ike_selector_to_id(sel, bfalse);

    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s2->data.idi);
    x4_ike_message_appendb(&xchg->out.pkt, x4c_ike_pt_id, &s2->data.idr);
  }

  /* hash the packet */
  x4_ike_compute2_hash2(s2, &xchg->out.pkt, xchg->out.pkt.data+28+4);

  return x4_ike_exchange_send(xchg,0);
}

bval x4_ike_q_recv3(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /* r > HDR*, HASH(3)  */
  x4s_ike_message * m = &xchg->in.msg;
  x4s_ike_payload * hash;
  uint8  hv[x4c_hash_max];
  
  x4_assert(xchg->seqno == 2);

  /*  */
/*
  if (! VERIFY_PAYLOADS(m, PT_HASH, 0, 0))
    return x4_warn("q_recv3: wrong payload(s) (%x)\n", m->mask_t), bfalse;
*/

  /* validate hash */
  hash = m->by_type[x4c_ike_pt_hash];

  if (hash->body.len != s1->sa.hasher->hlen)
    return x4_warn("q_recv3: invalid hash len\n"), bfalse;

  x4_ike_compute2_hash3(s2, hv);
  if (x4_memcmp(hash->body.data, hv, hash->body.len))
    return x4_warn("q_recv3: invalid hash\n"), bfalse;

  /*  */
  if (s2->sa.c.group)
    if (! x4_dh_complete(&s2->data.ke))
    {
      x4_ike_exchange_die(xchg);
      return x4_warn("q_recv3: failed to compute DH secret\n"),bfalse;
    }      

  /* compute keymat */
  x4_ike_compute2_keymat(s2);

  return btrue;
}

bval x4_ike_q_send4(x4s_ike_exchange * xchg)
{
  x4s_ike_phase2 * s2 = (x4_assert(xchg && xchg->modedata), xchg->modedata);
  x4s_ike_phase1 * s1 = (x4_assert(s2->s1), s2->s1);

  /* r > HDR*, HASH, N */
  uint8 nv [sizeof(x4s_isakmp_notify)-1+4];

  x4_assert(xchg->seqno == 3);
  x4_assert(s2->data.commit);

  x4_ike_sx_format_notify4(x4c_ike_nms_connected, s2->sa.k.spi_l, nv);

  /* format message */
  x4_ike_message_create(&xchg->out.pkt, s1->ci, s1->cr, xchg->et, s2->msgid);
  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_hash, 
                        0, s1->sa.hasher->hlen);
  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_n, nv, sizeof(nv));
  
  /* hash the packet */
  x4_ike_compute2_hash1(s2->msgid, s1, &xchg->out.pkt, xchg->out.pkt.data+28+4);

  return x4_ike_exchange_send(xchg,0);
}


/*
 *
 */
bval _s2r_process_sa(x4s_ike_phase2 * s2)
{
  x4s_ike_exchange * xchg = &s2->xchg;
  x4s_ike_sa_payload sa;
  x4s_ike_sa_attribute * a;

  x4_assert(s2);

  /*  */
  if (! x4_ike_sa_unpack(&s2->sa.raw, &sa))
    return bfalse;

  /* process only one proposal (must be ESP) with only one transform */
  if (sa.doi != x4c_ike_doi_ipsec ||
      sa.pr[0].proto != x4c_ike_proto_ipsec_esp || 
      sa.pr[1].index ||
      ! sa.pr[0].tr[0].index || 
      sa.pr[0].tr[1].index)
    return x4_warn("_s2r_process_sa: unsupported SA proposal\n"), bfalse;

  if (sa.pr[0].spi.len != 4)
    return x4_warn("_s2r_process_sa: invalid SPI len\n"), bfalse;

  s2->sa.c.cipher = sa.pr[0].tr[0].type;

  for (a = sa.pr[0].tr[0].attr; a->type; a++)
    switch (a->type)
    {
    case x4c_ike_a2_encapsulation_mode: 
      {
        uint16 encaps = (uint16)a->val; 

        /* normalize NAT-T draft values */
        switch (encaps)
        {
        case x4c_ike_a2e_01_tunnel:
        case x4c_ike_a2e_05_tunnel: encaps = x4c_ike_a2e_tunnel; break;

        case x4c_ike_a2e_01_transport:
        case x4c_ike_a2e_05_transport: encaps = x4c_ike_a2e_transport; break;
        }

        s2->sa.c.encaps = encaps;
      }
      break;

    case x4c_ike_a2_auth_algorithm:
      s2->sa.c.auth = (uint16)a->val;
      break;

    case x4c_ike_a2_key_length:
      s2->sa.c.kbits = (uint16)a->val;
      break;

    case x4c_ike_a2_oakley_group:
      s2->sa.c.group = (uint16)a->val;
      break;

    case x4c_ike_a2_life_type:
      {
        uint8 type = a->type;
        
        if (++a->type != x4c_ike_a2_life_duration)
          return x4_warn("s2_process_sa: invalid lifetime attr\n"), bfalse;

        switch (type)
        {
        case x4c_ike_a1l_seconds  : s2->sa.c.lifetime.seconds = a->val; break;
        case x4c_ike_a1l_kilobytes: s2->sa.c.lifetime.kbytes = a->val; break;

        default:
          x4_warn("s2_process_sa: unknown lifetime type\n");
        }
      }
      break;
    
    default:
      x4_info("_s2r_process_sa: implement me, sa.attr %u\n", a->type);
    };

  if (!s2->sa.c.encaps || !s2->sa.c.cipher && !s2->sa.c.auth)
    return x4_info("_s2r_process_sa: invalid SA proposal\n"), bfalse;

  s2->sa.k.spi_r = *(uint32*)sa.pr[0].spi.data;
  return btrue;
}
