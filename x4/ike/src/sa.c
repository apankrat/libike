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
 *	$Id: sa.c,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#include "isakmp.h"

#include "x4/ike/sa.h"
#include "x4/ike/const.h"
#include "x4/core/bswap.h"

/*
 *  -- local functions --
 */
static bval _sa_unpack_proposal(x4s_buf_walker * , x4s_ike_sa_proposal * , 
                                uint8 * np);

static bval _sa_unpack_transform(x4s_buf_walker * , x4s_ike_sa_transform * , 
                                 uint8 * np);

static bval _sa_unpack_attribute(x4s_buf_walker * , x4s_ike_sa_attribute * );

static void _sa_pack_proposal(const x4s_ike_sa_proposal * , x4s_buf * , 
                              bval last);

static void _sa_pack_transform(const x4s_ike_sa_transform * , x4s_buf * , 
                               bval last);

static void _sa_pack_attribute(const x4s_ike_sa_attribute * , x4s_buf * );

static x4s_isakmp_payload * _sa_fetch_payload(x4s_buf_walker * , uint8 np);

/*
 *
 */
bval x4_ike_sa_unpack(const x4s_buf * pkt, x4s_ike_sa_payload * sa)
{
  x4s_buf_walker wlk;
  uint32 * p32;
  uint     i;
  uint8    np;
  
  x4_assert(pkt && sa);
  
  /*  */
  x4_memset(sa, 0, sizeof(x4s_ike_sa_payload));
  x4_walker_init(&wlk, (x4s_buf*)pkt);

  /* - header - */
  if (! (p32 = x4_walker_fetch(&wlk, 4)) )
    return x4_warn("sa: too short\n"), bfalse;
  sa->doi = x4_bswap32(*p32);

  if (! (p32 = x4_walker_fetch(&wlk, 4)) )
    return x4_warn("sa: too short\n"), bfalse;
  sa->sit = x4_bswap32(*p32);

  /* parse proposals */
  for (i=0; i<x4c_ike_proposal_max; i++)
  {
    if (! _sa_unpack_proposal(&wlk, &sa->pr[i], &np))
      return bfalse;
    if (! np);
      break;
  }

  if (np)
    return x4_warn("sa: too manu proposals\n"), bfalse;

  if (x4_walker_size(&wlk) != 0)
    return x4_warn("sa: too long\n"), bfalse;

  return btrue;  
}

/*  */
void x4_ike_sa_pack(const x4s_ike_sa_payload * sa, x4s_buf * pkt)
{
  uint32 v32;
  uint i;
  
  x4_assert(sa && pkt);

  /*  */
  v32 = x4_bswap32(sa->doi);
  x4_buf_assign(pkt, &v32, 4);

  v32 = x4_bswap32(sa->sit);
  x4_buf_append(pkt, &v32, 4);

  for (i=0; sa->pr[i].index; i++)
    _sa_pack_proposal(&sa->pr[i], pkt, !sa->pr[i+1].index);
}

/*  */
int x4_ike_sa_compare(const x4s_buf * sa1b, const x4s_buf * sa2b, 
                      uint32 * spi)
{
  x4s_ike_sa_payload     sa1, sa2;
  x4s_ike_sa_proposal  * pr1 = sa1.pr, * pr2 = sa2.pr;
  x4s_ike_sa_transform * tr1 = pr1->tr, * tr2 = pr2->tr;
  x4s_ike_sa_attribute * a1 = tr1->attr, * a2 = tr2->attr;

  /*
   * it's is pretty dumb for now - assumes that there is 
   * only one proposal with a single transform
   */

  x4_assert(sa1b && sa2b);

  /*  */
  if (! x4_ike_sa_unpack(sa1b, &sa1) ||
      ! x4_ike_sa_unpack(sa2b, &sa2))
    return 1;

  /*  */
  if (sa1.doi != sa2.doi ||
      sa1.sit != sa2.sit)
    return 1;

  /*  */
  if (pr1->index != pr2->index ||
      pr1->proto != pr2->proto)
    return 1;

/*
  $todo

  ISAKMP SA SPI = node's cookie, ie i>r SPI is CKY-I,
                                    i<r SPI is CKY-R

  if (pr1->proto == proto_isakmp && pr1->spi.len && pr2->spi.len ||
      pr1->proto != proto_isakmp)
    if(! spi && buf_compare(&pr1->spi, &pr2->spi))
      return 1;
*/

  /*  */
  if (tr1->index != tr2->index ||
      tr1->type != tr2->type)
    return 1;

  /*  */
  for ( ; a1->type; a1++)
  {
    x4s_ike_sa_attribute * b2;

    for (b2 = a2; b2->type; b2++)
      if (b2->type == a1->type && b2->val == a1->val)
        break;

    if (! b2->type)
      return 1;
  }
  
  if (spi)
  {
    x4_assert(pr1->spi.len == 4);
    *spi = *(uint32*)pr2->spi.data;
  }
  return 0;
}

/*
 *  -- local methods --
 */
bval _sa_unpack_proposal(x4s_buf_walker * wlk, 
                         x4s_ike_sa_proposal * pr, uint8 * np)
{
  x4s_isakmp_payload * ip;
  uint8 * data;
  uint i;

  /*  */
  x4_assert(wlk && pr && np);

  /*  */
  ip = _sa_fetch_payload(wlk, x4c_ike_pt_p);
  if (! ip)
    return bfalse;

  data = x4_walker_fetch(wlk, 4);
  x4_assert(data);
  
  pr->index = data[0];
  pr->proto = data[1];

  if (data[2])
  {
    if (x4_bswap16(ip->len) < 4 + 4 + data[2])
      return x4_warn("sa: invalid len\n") , bfalse;

    x4_buf_attach(&pr->spi, x4_walker_fetch(wlk, data[2]), data[2]);
  }

  if (data[3] > x4c_ike_transform_max)
    return x4_warn("sa: too many transforms\n"), bfalse;

  for (i=0; i<data[3]; i++)
  {
    if (! _sa_unpack_transform(wlk, &pr->tr[i], np))
      return bfalse;

    if (i+1<data[3] && !*np)
      return x4_warn("sa: invalid next payload\n"), bfalse;
  }

  if (*np)
    return x4_warn("sa: invalid next payload\n"), bfalse;

  *np = ip->np;
  return btrue;
}

/*  */
bval _sa_unpack_transform(x4s_buf_walker * wlk, 
                          x4s_ike_sa_transform * tr, uint8 * np)
{
  x4s_isakmp_payload * ip;
  uint8 * data;
  uint i, end;

  /*  */
  x4_assert(wlk && tr && np);

  /*  */
  ip = _sa_fetch_payload(wlk, x4c_ike_pt_t);
  if (! ip)
    return bfalse;

  data = x4_walker_fetch(wlk, 4);
  x4_assert(data);

  tr->index = data[0];
  tr->type  = data[1];

  if (data[2] || data[3])
    return x4_warn("sa: invalid reserved\n"), bfalse;

  /* parse attributes */
  end = x4_walker_pos(wlk) + x4_bswap16(ip->len) - 8;

  for (i=0; i<x4c_ike_attribute_max; i++)
  {
    if (x4_walker_pos(wlk) >= end)
      break;
    
    if (! _sa_unpack_attribute(wlk, &tr->attr[i]))
      return x4_warn("sa: invalid attribute\n"), bfalse;
  }

  if (i == x4c_ike_attribute_max)
    return x4_warn("sa: too many attributes\n"), bfalse;

  if (x4_walker_pos(wlk) > end)
    return x4_warn("sa: attributes are too long\n"), bfalse;

  *np = ip->np;
  return btrue;
}

/*  */
bval _sa_unpack_attribute(x4s_buf_walker * wlk, x4s_ike_sa_attribute * attr)
{
  uint16 * type;
  uint16 * v16 = 0;
  uint32 * v32 = 0;

  /*  */
  x4_assert(wlk && attr);
  
  if (! (type = x4_walker_fetch(wlk, 2)) )
    return bfalse;

  /* type */
  attr->type = x4_bswap16(*type) & 0x7FFF;

  /* value */
  if (*type & x4m_bswap16(0x8000))
  {
    v16 = x4_walker_fetch(wlk, 2);
  }
  else
  {
    uint16 * pval = x4_walker_fetch(wlk, 2);

    if (! pval)
      return bfalse;

    *pval = x4_bswap16(*pval);

    switch (*pval)
    {
    case 2: v16 = x4_walker_fetch(wlk, 2); break;
    case 4: v32 = x4_walker_fetch(wlk, 4); break;
    default:
      return x4_warn("sa: ignoring attribute %u with len of %u\n",
                     x4m_uint8(attr->type), x4m_uint8(*pval)), 
             bfalse;
    }
  }
  x4_assert(v16 || v32);

  if (v16) attr->val = x4_bswap16(*v16);
  else     attr->val = x4_bswap32(*v32);

  return btrue;
}

/*  */
void _sa_pack_proposal(const x4s_ike_sa_proposal * pr, 
                       x4s_buf * pkt, bval last)
{
  x4s_isakmp_payload ip = { 0 };
  uint ip_off, tr_off, i;
  
  /*  */
  x4_assert(pr && pkt);

  /* reserve header space */
  ip_off = pkt->len;
  x4_buf_append(pkt, 0, sizeof(ip)-1);

  /*  */
  x4_buf_append(pkt, &pr->index, 1);
  x4_buf_append(pkt, &pr->proto, 1);
  x4_buf_append(pkt, &pr->spi.len, 1);

  tr_off = pkt->len;
  x4_buf_append(pkt, 0, 1);                      /* transform count */
  x4_buf_append(pkt, pr->spi.data, pr->spi.len);

  for (i=0; pr->tr[i].index; i++)
    _sa_pack_transform(&pr->tr[i], pkt, !pr->tr[i+1].index);

  /* write number of transforms */
  pkt->data[tr_off] = i;

  /* write payload header */
  ip.np = last ? 0 : x4c_ike_pt_p;
  ip.len = x4_bswap16( (uint16)(pkt->len-ip_off) );
  x4_memmove(pkt->data+ip_off, &ip, sizeof(ip)-1);  
}

/*  */
void _sa_pack_transform(const x4s_ike_sa_transform * tr, 
                        x4s_buf * pkt, bval last)
{
  x4s_isakmp_payload ip = { 0 };
  uint ip_off, i;

  /*  */
  x4_assert(tr && pkt);

  /* reserve header space */
  ip_off = pkt->len;
  x4_buf_append(pkt, 0, sizeof(ip)-1);

  /*  */
  x4_buf_append(pkt, &tr->index, 1);
  x4_buf_append(pkt, &tr->type, 1);
  x4_buf_append(pkt, 0, 2);             /* reserved */

  for (i=0; tr->attr[i].type; i++)
    _sa_pack_attribute(&tr->attr[i], pkt);

  /* write payload header */
  ip.np = last ? 0 : x4c_ike_pt_t;
  ip.len = x4_bswap16( (uint16)(pkt->len-ip_off) );
  x4_memmove(pkt->data+ip_off, &ip, sizeof(ip)-1);  
}

/*  */
void _sa_pack_attribute(const x4s_ike_sa_attribute * attr, x4s_buf * pkt)
{
  uint16 t;

  /*  */
  x4_assert(attr && pkt);
  x4_assert(attr->type);

  /*  */
  if (attr->val < 0x10000)
  {
    uint16 v;

    v = x4_bswap16( (uint16)attr->val );
    t = x4_bswap16( (uint16)(attr->type | 0x8000) );

    x4_buf_append(pkt, &t, 2);
    x4_buf_append(pkt, &v, 2);
  }
  else
  {
    uint32 v = x4_bswap32(attr->val);
    uint16 l;

    v = x4m_bswap16(4);
    t = x4_bswap16(attr->type);

    x4_buf_append(pkt, &t, 2);
    x4_buf_append(pkt, &l, 2);
    x4_buf_append(pkt, &v, 4);
  }
}

/*  */  
x4s_isakmp_payload * _sa_fetch_payload(x4s_buf_walker * wlk, uint8 np)
{
  x4s_isakmp_payload * ip;

  /*  */
  x4_assert(wlk);

  /*  */
  ip = x4_walker_fetch(wlk, 4);
  if (! ip)
    return x4_warn("sa: too short\n"), (void*)0;

  if (x4_bswap16(ip->len) > x4_walker_size(wlk) + 4 ||
      x4_bswap16(ip->len) < 4 + 4)
    return x4_warn("sa: invalid len\n"), (void*)0;

  if (ip->reserved)
    return x4_warn("sa: invalid reserved\n"), (void*)0;
  
  if (ip->np != np && ip->np != 0)
    return x4_warn("sa: invalid next payload %u\n", x4m_uint8(ip->np)), 
           (void*)0;

  return ip;
}

