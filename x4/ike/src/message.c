/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: message.c,v 1.5 2003/04/10 03:45:41 alex Exp $
 */

#include "message.h"
#include "x4/core/bswap.h"

/* zero cookie */
static const uint8 _ck0[8] = { 0 };

/*  */
#define BIT(v)  (1L << (v))

/*
 *
 */
bval x4_ike_message_unpack(x4s_buf * pkt, x4s_ike_message * m, size_t blen)
{
  x4s_buf_walker wlk;
  uint8  np;
  size_t plen, mlen;
  uint   i;

  x4_assert(pkt && m);

  /*  */
  x4_memset(m, 0, sizeof(x4s_ike_message));

  x4_walker_init(&wlk, pkt);

  /* fetch isakmp header */
  m->hdr = x4_walker_fetch(&wlk, 28);
  if (! m->hdr)
    return x4_warn("header: too small (%u)\n", x4_walker_size(&wlk)), bfalse;

  /* validate header */
  if (m->hdr->ver != 0x10)
    return x4_warn("header: invalid version (%02x)\n", 
                   x4m_uint8(m->hdr->ver)), bfalse;

  if (x4_bswap32(m->hdr->len) != pkt->len)
    return x4_warn("header: invalid length (%u)\n", 
                   x4_bswap32(m->hdr->len)), bfalse;

  if (! (x4c_ike_et_base <= m->hdr->et && 
         m->hdr->et <= x4c_ike_et_informational) &&

      ! (x4c_ike_et_quick_mode <= m->hdr->et && 
         m->hdr->et <= x4c_ike_et_new_group_mode))

    return x4_warn("header: invalid exchange type (%u)\n", 
                   x4m_uint8(m->hdr->et)), bfalse;

  if (m->hdr->flags & x4c_ike_hf_reserved)
    return x4_warn("header: invalid flags (%02x)\n", 
                   x4m_uint8(m->hdr->flags)), bfalse;

  if (m->hdr->flags & x4c_ike_hf_commit && ! m->hdr->msgid)
    return x4_warn("header: commit flag in phase 1 ike_message\n"), bfalse;

  if (m->hdr->flags & x4c_ike_hf_auth_only)
    x4_warn("header: authentication_only flag present\n");

  /* parse payloads */
  np = m->hdr->np;

  for (i=0; i<x4c_ike_payload_max; i++)
  {
    x4s_ike_payload * p = &m->by_order[i];
    x4s_isakmp_payload * ip;

    ip = x4_walker_fetch(&wlk, 4);
    if (! ip)
      return x4_warn("payload: premature end of packet\n"), bfalse;

    /* bring NAT-T payload IDs to the common denominator */
    switch (np)
    {
    case x4c_ike_pt_01_natd:  np = x4c_ike_pt_natd; break;
    case x4c_ike_pt_01_natoa: np = x4c_ike_pt_natoa; break;
    }
    
    /* validate */
    if (np < x4c_ike_pt_sa || 
        x4c_ike_pt_v < np && np < x4c_ike_pt_natd ||
        x4c_ike_pt_natoa < np)
      return x4_warn("payload: invalid next ike_payload (%02x)\n", 
                     x4m_uint8(np)), bfalse;

    if (ip->reserved)
      return x4_warn("payload: invalid reserved (%04x)\n", ip->reserved), 
             bfalse;

    plen = x4_bswap16(ip->len);
    if (plen < 4+1 || x4_walker_size(&wlk) + 4 < plen)
      return x4_warn("payload: invalid length (%u)\n", plen), bfalse;

    /* $add payload-specific length checks here */
    if (np == x4c_ike_pt_nonce)
      if (plen < 4+8 || 4+256 < plen) 
        return x4_warn("payload: invalid nonce len (%u)\n", plen-4), bfalse;

    /*  */
    p->type = np;
    plen -= 4;
    x4_buf_attach(&p->body, ip->data, plen);

    /*  */
    if (m->mask_t & BIT(np))
      m->mask_r |= BIT(np);
    else
    {
      m->mask_t |= BIT(np);
      m->by_type[np] = p;
    }

    /* advance */
    x4_walker_fetch(&wlk, plen);

    np = ip->np;
    if (! np)
      break;
  }

  if (i == x4c_ike_payload_max)
    return x4_warn("message: too many payloads\n"), bfalse;

  /* validate x4s_ike_message length */
  mlen = x4_walker_pos(&wlk);   /* (packet size) - (encryption pad size)  */
  
  if (mlen < pkt->len)
  {
    uint8 * z;

    if (! (m->hdr->flags & x4c_ike_hf_encryption))
      return x4_warn("message: uneven length\n"), bfalse;

    /* validate pad length */
    plen = x4_walker_size(&wlk);
    if (plen > blen)
      return x4_warn("message: pad is too big\n"), bfalse;

    /* validate pad content */
    z = x4_walker_fetch(&wlk, plen);
    while (plen--)
      if (*z++)
        return x4_warn("message: invalid pad byte\n"), bfalse;
  }

  x4_buf_attach(&m->pkt, m->hdr, mlen);

  return btrue;
}

/*
 *
 */
void x4_ike_message_create(x4s_buf * pkt, 
                           uint8 * ci, uint8 * cr, 
                           uint8 et, uint32 msgid)
{
  x4s_isakmp_header * hdr;

  x4_assert(pkt && ci && cr);
  
  hdr = x4_buf_resize(pkt, 28);
  x4_assert(hdr);

  x4_memmove(hdr->ci, ci, 8);
  x4_memmove(hdr->cr, cr, 8);
  hdr->np = 0;
  hdr->ver = 0x10;
  hdr->et = et;
  hdr->flags = 0;
  hdr->msgid = msgid;
  hdr->len = x4m_bswap32(28);
}

/*
 *
 */
void x4_ike_message_append(x4s_buf * pkt, 
                           uint8 pt, 
                           const void * data, size_t len)
{
  x4s_isakmp_header * hdr;
  x4s_isakmp_payload * ip;
  uint8 * np;
  uint    ip_off;

  x4_assert(pkt && pkt->len >= 28 && pt && len);

  /*  */
  hdr = (x4s_isakmp_header *)(pkt->data);
  hdr->len = x4_bswap32(len + x4_bswap32(hdr->len) + 4);

  ip = (x4s_isakmp_payload *)(hdr + 1);
  np = &hdr->np; 
  
  while (*np)
  {
    np = &ip->np;
    ip = (x4s_isakmp_payload*)(x4_bswap16(ip->len) + (uint8*)ip);
  }

  *np = pt;
  ip_off = (uint8*)ip - pkt->data;
  x4_assert(ip_off <= pkt->len);

  x4_buf_append(pkt, 0, 4);
  x4_buf_append(pkt, data, len);

  ip = (x4s_isakmp_payload*)(pkt->data + ip_off);
  ip->len = x4_bswap16((uint16)(len+4));
}
