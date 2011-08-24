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
 *	$Id: phasex.c,v 1.4 2003/04/10 03:45:41 alex Exp $
 */

#include "phasex.h"
#include "phase2.h"
#include "utils.h"

#include "x4/core/bswap.h"
#include "x4/crypto/random.h"

/* local functions */
static bval _sx_recv_notify(x4s_ike_phase1 * s1, x4s_buf * body);
static bval _sx_recv_delete(x4s_ike_phase1 * s1, x4s_buf * body);

static bval _sx_purge_spi(x4s_ike_phase1 * s1, uint8 proto, 
                          uint8 * spi, size_t spilen);

/*
 *
 */
bval x4_ike_sx_check_notify(const x4s_buf * b, size_t spilen)
{
  x4s_isakmp_notify * ip = (x4s_isakmp_notify *)(x4_assert(b), b->data);
  
  if (b->len < sizeof(x4s_isakmp_notify) ||
      b->len < sizeof(x4s_isakmp_notify)+ip->spi_len)
    return x4_warn("sx_check_notify: too small\n"), bfalse;

  if (ip->doi != x4m_bswap32(x4c_ike_doi_ipsec))
    return x4_warn("sx_check_notify: invalid doi\n"), bfalse;

  if (spilen && spilen != ip->spi_len)
    return x4_warn("sx_check_notify: invalid spi len\n"), bfalse;

  return btrue;
}

/*  */
size_t x4_ike_sx_format_notify4(uint16 code, uint32 spi, uint8 * buf)
{
  x4s_isakmp_notify * ip = (x4s_isakmp_notify *)(x4_assert(buf), buf);

  x4_assert(code && spi);

  ip->doi   = x4m_bswap32(x4c_ike_doi_ipsec);
  ip->proto = x4c_ike_proto_isakmp;
  ip->type  = x4_bswap16(code);
  ip->spi_len = 4;
  x4_memmove(ip+1, &spi, 4);

  return sizeof(x4s_isakmp_header)+4;
}

/*  */
size_t x4_ike_sx_format_notify16(uint16 code, uint8 * ci, uint8 * cr, 
                                 uint8 * buf)
{
  x4s_isakmp_notify * ip = (x4s_isakmp_notify *)(x4_assert(buf), buf);
  uint8 * spi = (uint8*)(ip+1);

  x4_assert(code && ci && cr);

  ip->doi   = x4m_bswap32(x4c_ike_doi_ipsec);
  ip->proto = x4c_ike_proto_isakmp;
  ip->type  = x4_bswap16(code);
  ip->spi_len = 16;
  x4_memmove(spi, ci, 8);
  x4_memmove(spi+8, cr, 8);

  return sizeof(x4s_isakmp_header)+16;
}

/*  */
bval x4_ike_sx_send_inf(x4s_ike_phase1 * s1, uint16 code, uint32 spi)
{
  /*
   *  > HDR(INF)*, HASH(1), N
   *  > HDR(INF),  N(code)
   */
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);

  bval   enc  = x4m_sa1_established(s1);
  uint32 msgid;
  uint8  nv [sizeof(x4s_isakmp_notify) + 16];
  uint8  iv [x4c_iv_max];
  size_t nlen = sizeof(x4s_isakmp_notify);

  /*  */
  x4_assert(s1); /* $todo - other cases */

  /*  */
  x4_random(&msgid, 4);

  nlen += spi ? x4_ike_sx_format_notify4(code, spi, nv) : 
                x4_ike_sx_format_notify16(code, s1->ci, s1->cr, nv);
  
  x4_ike_message_create(&xchg->out.pkt, s1->ci, s1->cr, 
                        x4c_ike_et_informational, msgid);

  if (enc)
    x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_hash, 
                          0, s1->sa.hasher->hlen);

  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_n, nv, nlen);
  
  if (enc)
  {
    x4_ike_compute2_hash1(msgid, s1, &xchg->out.pkt, xchg->out.pkt.data+28+4);
    x4_ike_compute2_iv(msgid, s1, iv);
  }
  
  return x4_ike_exchange_send(xchg, iv);
}

/*  */
bval x4_ike_sx_recv_inf(x4s_ike_phase1 * s1)
{
  /*
   * i < HDR(INF),  N/D
   * i < HDR(INF)*, HASH(1), N/D 
   */
  x4s_ike_message * m = (x4_assert(s1), &s1->xchg.in.msg);
  x4s_ike_payload * hash = 0;
  x4s_ike_payload * main;

  /*  */
  x4_assert(s1);

  /* validate */
  if (m->mask_r)
    return x4_warn("sx_recv_inf: redundant payload(s) (%x)\n", m->mask_r), 
           bfalse;

  if (m->hdr->flags & x4c_ike_hf_encryption)
  {
    if (m->by_order[0].type != x4c_ike_pt_hash)
      return x4_warn("sx_recv_inf: 1st payload is not HASH\n"), bfalse;

    hash = &m->by_order[0];
    m->mask_t &= ~HASH;
  }

  switch (m->mask_t)
  {
  case N: main = m->by_type[x4c_ike_pt_n]; break;
  case D: main = m->by_type[x4c_ike_pt_d]; break;
  default:
    return x4_warn("sx_recv_inf: invalid payload(s) (%x)\n", m->mask_t), 
           bfalse;
  }

  /* validate hash */
  if (hash)
  {
    uint8 hv[x4c_hash_max];

    if (hash->body.len != s1->sa.hasher->hlen)
      return x4_warn("sx_recv_inf: invalid hash len\n"), bfalse;

    x4_ike_compute2_hash1(m->hdr->msgid, s1, &m->pkt, hv);

    if (x4_memcmp(hash->body.data, hv, hash->body.len))
      return x4_warn("sx_recv_inf: invalid hash\n"), bfalse;
  }

  /* process */
  if (main->type == x4c_ike_pt_n)
    return _sx_recv_notify(s1, &main->body);

  if (main->type == x4c_ike_pt_d)
    return _sx_recv_delete(s1, &main->body);

  x4_assert(0);
  return bfalse;
}

/*  */
bval x4_ike_sx_send_delete(x4s_ike_phase1 * s1, uint32 spi)
{
  /*
   *  > HDR(INF)*, HASH(1), D
   *  > HDR(INF),  D(code)
   */
  x4s_ike_exchange * xchg = (x4_assert(s1), &s1->xchg);
  bval   enc  = x4m_sa1_established(s1);
  uint32 msgid;

  uint8  dv [sizeof(x4s_isakmp_delete) + 16];
  uint8  iv [x4c_iv_max];
  size_t dlen = sizeof(x4s_isakmp_delete);

  x4s_isakmp_delete * d = (x4s_isakmp_delete*)dv;

  /*  */
  x4_assert(s1); /* $todo - other cases */

  /*  */
  x4_random(&msgid, 4);

  d->doi       = x4m_bswap32(x4c_ike_doi_ipsec);
  d->proto     = spi ? x4c_ike_proto_ipsec_esp : x4c_ike_proto_isakmp;
  d->spi_len   = spi ? 4 : 16;
  d->spi_count = x4m_bswap16(1);
  dlen        += d->spi_len; /*  *x4_bswap16(d->spi_count); */

  if (! spi)
  {
    x4_memmove(d+1, s1->ci, 8);
    x4_memmove(d+2, s1->cr, 8); /* hack hack */
  }
  else
    x4_memmove(d+1, &spi, 4);

  x4_ike_message_create(&xchg->out.pkt, s1->ci, s1->cr, 
                        x4c_ike_et_informational, msgid);

  if (enc)
    x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_hash, 
                          0, s1->sa.hasher->hlen);

  x4_ike_message_append(&xchg->out.pkt, x4c_ike_pt_d, dv, dlen);

  if (enc)
  {
    x4_ike_compute2_hash1(msgid, s1, &xchg->out.pkt, xchg->out.pkt.data+28+4);
    x4_ike_compute2_iv(msgid, s1, iv);
  }

  return x4_ike_exchange_send(xchg, iv);
}

/*
 *
 */
bval _sx_recv_notify(x4s_ike_phase1 * s1, x4s_buf * body)
{
  x4s_isakmp_notify * ip;
  uint16 type;
  
  x4_assert(s1 && body);

  /*  */
  if (body->len < sizeof(x4s_isakmp_notify))
    return x4_warn("sx_recv_notify: too small\n"), bfalse;

  ip = (x4s_isakmp_notify*)body->data;

  if (ip->doi != x4m_bswap32(x4c_ike_doi_ipsec))
    return x4_warn("sx_recv_notify: invalid doi\n"), bfalse;

  if (body->len < sizeof(x4s_isakmp_notify) + ip->spi_len)
    return x4_warn("sx_recv_notify: too small\n"), bfalse;

  /*  */
  type = x4_bswap16(ip->type);
  switch (type)
  {
  case x4c_ike_nms_connected:
  case x4c_ike_nms_responder_lifetime:
  case x4c_ike_nms_replay_status:
  case x4c_ike_nms_initial_contact:

    /* $todo - more checks here. check ip->spi against xchg->spi  */

    x4_logf(x4c_l_info, "sx_recv_notify: status message %u\n", type);
    break;
    
  default:  
    /* an error message  */
    x4_logf(x4c_l_info, "sx_recv_notify: error %u\n", type);

    if (! _sx_purge_spi(s1, ip->proto, (uint8*)(ip+1), ip->spi_len))
      return bfalse;      
  };  

  return btrue;
}

/*  */
bval _sx_recv_delete(x4s_ike_phase1 * s1, x4s_buf * body)
{
  x4s_isakmp_delete * ip;
  uint16 n;
  uint8 * spi;
  
  x4_assert(s1 && body);

  /*  */
  if (body->len < sizeof(x4s_isakmp_delete))
    return x4_logf(x4c_l_warn,"_sx_recv_delete: too small\n"), bfalse;

  ip = (x4s_isakmp_delete*)body->data;

  if (ip->doi != x4m_bswap32(x4c_ike_doi_ipsec))
    return x4_warn("sx_recv_delete: invalid doi\n"), bfalse;

  n = x4_bswap16(ip->spi_count);

  if (body->len != sizeof(x4s_isakmp_delete) + n*ip->spi_len)
    return x4_warn("sx_recv_delete: uneven len\n"), bfalse;

  /*  */
  for (spi = (uint8*)(ip+1); n; n--, spi+=ip->spi_len)
    if (_sx_purge_spi(s1, ip->proto, spi, ip->spi_len))
      break;

  return btrue;
}

/*  */
bval _sx_purge_spi(x4s_ike_phase1 * s1, uint8 proto, uint8 * spi, size_t len)
{
  x4s_ike_phase2 * s2;
  
  /*  */
  x4_assert(s1);
  
  switch (proto)
  {
  case x4c_ike_proto_isakmp:
  
    if (len != 0 && len != 16)
      return x4_warn("sx_purge_spi: invalid spi len\n"), bfalse;

    if (len)
      if (x4_memcmp(s1->ci, spi, 8) || 
          x4_memcmp(s1->cr, spi+8, 8) && (s1->xchg.seqno > 1))
        return x4_warn("sx_purge_spi: wrong isakmp spi\n"), bfalse;

    x4_logf(x4c_l_info, "sx_purge_spi: removing phase 1\n");
    x4_ike_exchange_die(&s1->xchg);
    break;

  case x4c_ike_proto_ipsec_esp:

    if (len != 4)
      return x4_warn("sx_purge_spi: invalid spi len\n"), bfalse;

    if (! *(uint32*)spi)
      return x4_warn("sx_purge_spi: zero spi\n"), bfalse;

    for (s2 = s1->s2; s2; s2 = s2->next)
      if (s2->sa.k.spi_l == *(uint32*)spi ||
          s2->sa.k.spi_r == *(uint32*)spi)
        break;

    if (! s2)
      return x4_warn("sx_purge_spi: unknown spi\n"), bfalse;

    x4_logf(x4c_l_info, "sx_purge_spi: removing phase 2\n");
    x4_ike_exchange_die(&s2->xchg);
    break;

  default:

    x4_logf(x4c_l_info, "sx_purge_spi: implement me - %u\n", proto);
    return bfalse;
  }

  return btrue;
}

