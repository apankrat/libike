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
 *	$Id: utils.c,v 1.8 2003/04/27 21:37:37 alex Exp $
 */

#include "utils.h"

#include "x4/core/bswap.h"
#include "x4/crypto/hmac.h"

/* local functions */
static void _hv_to_iv(x4s_ike_phase1 * s1, const uint8 * hv, uint8 * iv);

/*  */
x4s_hasher_alg * x4_ike_select_hasher(uint16 v)
{
  switch (v)
  {
  case x4c_ike_a1h_md5 :     return x4v_md5;
  case x4c_ike_a1h_sha1:     return x4v_sha1;
  case x4c_ike_a1h_sha2_256: return x4v_sha2_256;
  case x4c_ike_a1h_sha2_384: return x4v_sha2_384;
  case x4c_ike_a1h_sha2_512: return x4v_sha2_512;
  case x4c_ike_a1h_tiger:    return x4v_tiger;
  }
  return 0;
}

/*  */
x4s_cipher_alg * x4_ike_select_cipher(uint16 v)
{
  switch (v)
  {
  case x4c_ike_a1e_des_cbc:      return x4v_des;
  case x4c_ike_a1e_3des_cbc:     return x4v_3des;
  case x4c_ike_a1e_aes_cbc:      return x4v_aes;
  case x4c_ike_a1e_blowfish_cbc: return x4v_blowfish;
  case x4c_ike_a1e_rc5_cbc:      return x4v_rc5;
  case x4c_ike_a1e_cast_cbc:     return x4v_cast;
  case x4c_ike_a1e_idea_cbc:     return x4v_idea;
  }

  return 0;
}

/*  */
x4s_buf x4_ike_select_prime(uint16 v)
{
  x4s_buf r = { 0 };

  #define HANDLE(bits) \
    case x4c_ike_a1g_modp_##bits : \
      x4_buf_attach(&r,x4v_ike_modp##bits,sizeof(x4v_ike_modp##bits)); \
      break;

  switch (v)
  {
  HANDLE(768);
  HANDLE(1024);
  HANDLE(1536);
  HANDLE(2048);
  HANDLE(3072);
  HANDLE(4096);
  HANDLE(6144);
  HANDLE(8192);
  }
  return r;

  #undef HANDLE
}

/*
 *
 */
void x4_ike_compute1_skeyids(x4s_ike_phase1 * s1)
{
  x4s_hasher * h;
  size_t hlen;
  
  /*  */
  x4_assert(s1);

  hlen = s1->sa.hasher->hlen;

  /*  */
  x4_buf_resize(&s1->data.skeyid_d, hlen);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid);
  x4_assert(h);

  x4_hasher_updateb(h, &s1->data.ke.gxy);
  x4_hasher_update (h, &s1->ci, 8);
  x4_hasher_update (h, &s1->cr, 8);
  x4_hasher_update (h, "\0", 1);
  x4_hasher_completeb(h, &s1->data.skeyid_d);

  /*  */
  x4_buf_resize(&s1->data.skeyid_a, hlen);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid);
  x4_assert(h);

  x4_hasher_updateb(h, &s1->data.skeyid_d);
  x4_hasher_updateb(h, &s1->data.ke.gxy);
  x4_hasher_update (h, &s1->ci, 8);
  x4_hasher_update (h, &s1->cr, 8);
  x4_hasher_update (h, "\1", 1);
  x4_hasher_completeb(h, &s1->data.skeyid_a);

  /*  */
  x4_buf_resize(&s1->data.skeyid_e, hlen);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid);
  x4_assert(h);

  x4_hasher_updateb(h, &s1->data.skeyid_a);
  x4_hasher_updateb(h, &s1->data.ke.gxy);
  x4_hasher_update (h, &s1->ci, 8);
  x4_hasher_update (h, &s1->cr, 8);
  x4_hasher_update (h, "\2", 1);
  x4_hasher_completeb(h, &s1->data.skeyid_e);
}

/*  */
void x4_ike_compute1_enckey(x4s_ike_phase1 * s1)
{
  x4s_buf key = { 0 };
  size_t klen;
  
  x4_assert(s1);
  x4_assert(s1->data.skeyid_e.len);

  klen = s1->sa.klen;

  if (klen > s1->data.skeyid_e.len)
  {
    x4s_buf block = { 0 };
    x4s_hasher * h;

    /* 
     *  K  = K1 | K2 | K3
     *  K1 = prf(SKEYID_e, 0)
     *  K2 = prf(SKEYID_e, K1)
     *  K3 = prf(SKEYID_e, K2)
     */

    x4_buf_resize(&block, s1->sa.hasher->hlen);

    h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_e);
    x4_hasher_update(h, "\0", 1);
    x4_hasher_completeb(h, &block);

    for (;;)
    {
      x4_buf_appendb(&key, &block);
      if (key.len >= klen)
        break;

      h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_e);
      x4_hasher_updateb(h, &block);
      x4_hasher_completeb(h, &block);
    }

    x4_buf_resize(&key, klen);
  }
  else
  {
    x4_buf_attach(&key, s1->data.skeyid_e.data, klen);
  }

  /* expand the key into the schedule */
  s1->sa.key = s1->sa.cipher->init_ks(8*s1->sa.klen, key.data);
  x4_assert(s1->sa.key);

  s1->xchg.key = s1->sa.key;

  x4_buf_free(&key);
}

/*  */
void x4_ike_compute1_hashi(x4s_ike_phase1 * s1, uint8 * hv)
{
  x4s_hasher * h;
  
  x4_assert(s1 && hv);
  
  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid);
  x4_assert(h);
  
  x4_hasher_updateb(h, &s1->data.ke.gx);
  x4_hasher_updateb(h, &s1->data.ke.gy);
  x4_hasher_update (h, s1->ci, 8);
  x4_hasher_update (h, s1->cr, 8);
  x4_hasher_updateb(h, &s1->sa.raw);
  x4_hasher_updateb(h, &s1->data.idi);
  x4_hasher_complete(h, hv); 
}

/*  */
void x4_ike_compute1_hashr(x4s_ike_phase1 * s1, uint8 * hv)
{
  x4s_hasher * h;
  
  x4_assert(s1 && hv);
  
  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid);
  x4_assert(h);
  
  x4_hasher_updateb(h, &s1->data.ke.gy);
  x4_hasher_updateb(h, &s1->data.ke.gx);
  x4_hasher_update (h, s1->cr, 8);
  x4_hasher_update (h, s1->ci, 8);
  x4_hasher_updateb(h, &s1->sa.raw);
  x4_hasher_updateb(h, &s1->data.idr);
  x4_hasher_complete(h, hv); 
}

/*  */
void x4_ike_compute1_iv(x4s_ike_phase1 * s1)
{
  x4s_hasher * h;
  uint8  hv[x4c_hash_max];

  x4_assert(s1);

  h = s1->sa.hasher->instance();
  x4_assert(h);

  x4_hasher_updateb(h, &s1->data.ke.gx);
  x4_hasher_updateb(h, &s1->data.ke.gy);
  x4_hasher_complete(h, hv);

  _hv_to_iv(s1, hv, s1->xchg.iv);
}

/*  */
void x4_ike_compute2_iv(uint32 msgid, x4s_ike_phase1 * s1, uint8 * iv)
{
  x4s_hasher * h;
  uint8    hv[x4c_hash_max];

  x4_assert(msgid && s1 && iv);

  h = s1->sa.hasher->instance();
  x4_assert(h);

  x4_hasher_update(h, s1->xchg.iv, s1->sa.cipher->blen);
  x4_hasher_update(h, &msgid, 4);
  x4_hasher_complete(h, hv);

  _hv_to_iv(s1, hv, iv);
}

/*  */
void x4_ike_compute2_hash1(uint32 msgid, x4s_ike_phase1 * s1, 
                           x4s_buf * pkt, uint8 * hv)
{
  /* prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr ) */
  x4s_hasher * h;
  size_t  hlen;

  x4_assert(msgid && s1 && pkt && hv);

  hlen = s1->sa.hasher->hlen;
  x4_assert(pkt->len > 28+4+hlen);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_a);
  x4_assert(h);

  x4_hasher_update(h, &msgid, 4);
  x4_hasher_update(h, pkt->data+28+4+hlen, pkt->len-28-4-hlen);
  x4_hasher_complete(h, hv);
}

/*  */
void x4_ike_compute2_hash2(x4s_ike_phase2 * s2, x4s_buf * pkt, uint8 * hv)
{
  /* prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr ) */
  x4s_ike_phase1 * s1 = (x4_assert(s2 && s2->s1), s2->s1);
  x4s_hasher   * h;
  size_t  hlen;

  x4_assert(pkt && hv);

  hlen = s1->sa.hasher->hlen;
  x4_assert(pkt->len > 28+4+hlen);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_a);
  x4_assert(h);

  x4_hasher_update(h, &s2->msgid, 4);
  x4_hasher_updateb(h, &s2->data.ni);
  x4_hasher_update(h, pkt->data+28+4+hlen, pkt->len-28-4-hlen);
  x4_hasher_complete(h, hv);
}

void x4_ike_compute2_hash3(x4s_ike_phase2 * s2, uint8 * hv)
{
  /* prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b) */
  x4s_ike_phase1 * s1 = (x4_assert(s2 && s2->s1), s2->s1);
  x4s_hasher * h;

  x4_assert(hv);

  h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_a);
  x4_assert(h);

  x4_hasher_update(h, "\0", 1);
  x4_hasher_update(h, &s2->msgid, 4);
  x4_hasher_updateb(h, &s2->data.ni);
  x4_hasher_updateb(h, &s2->data.nr);
  x4_hasher_complete(h, hv);
}

/*  */
void x4_ike_compute2_keymat(x4s_ike_phase2 * s2)
{
  #define KEYMAT_ROUNDS 5
  /*
     KEYMAT = K1 | K2 | K3 | ...
      where
        K1 = prf(SKEYID_d,      [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
        K2 = prf(SKEYID_d, K1 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
        K3 = prf(SKEYID_d, K2 | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
        etc.
  */
  x4s_ike_phase1 * s1 = (x4_assert(s2 && s2->s1), s2->s1);
  uint     hlen = s1->sa.hasher->hlen;
  uint     i, j;
  uint8    proto = x4c_ike_proto_ipsec_esp;
  
  for (i=0; i<2; i++)
  {
    uint32   * spi    = i ? &s2->sa.k.spi_l : &s2->sa.k.spi_r;
    x4s_buf * keymat = i ? &s2->sa.k.key_l : &s2->sa.k.key_r;
    uint8 * block;

    x4_buf_resize(keymat, 5*hlen);
    block = keymat->data;

    for (j=0; j<KEYMAT_ROUNDS; j++)
    {
      x4s_hasher * h = x4_hmacb(s1->sa.hasher, &s1->data.skeyid_d);
      x4_assert(h);

      if (j) /* hash in previous keymat block */
        x4_hasher_update(h, block-hlen, hlen);

      if (s2->data.ke.gxy.len)
        x4_hasher_updateb(h, &s2->data.ke.gxy);

      x4_hasher_update (h, &proto, 1);
      x4_hasher_update (h, spi, 4);
      x4_hasher_updateb(h, &s2->data.ni);
      x4_hasher_updateb(h, &s2->data.nr);
      x4_hasher_complete(h, block);

      block += hlen;
    }
  }
}

/*
 *
 */
x4s_buf x4_ike_link_to_id(const x4s_net_link * l, bval local)
{
  x4s_buf id = { 0 };
  
  const x4u_net_ip * ip;
  uint8 type, ipl;

  x4_assert(l);
  ip = local ? &l->l.ip : &l->r.ip;

  /*  */
  switch (l->type)
  {
  case x4c_net_ip_v4: 
    type = x4c_ike_id_ipv4_addr;
    ipl = 4;
    break;

  case x4c_net_ip_v6:
    type = x4c_ike_id_ipv6_addr;
    ipl = 16;
    break;

  default:
    x4_assert(0);
    return id;
  }

  x4_buf_append(&id, &type, 1);
  x4_buf_append(&id, "\0", 1);     /* protocol  */
  x4_buf_append(&id, "\0\0", 2);   /* port      */
  x4_buf_append(&id, ip, ipl);

  return id;
}

/*  */
x4s_buf x4_ike_selector_to_id(const x4s_net_selector * s, bval local)
{
  x4s_buf id = { 0 };

  const x4s_net_socket_range * sr;
  uint8  type, ipl;
  uint16 port = 0;
  bval   range;

  /*  */
  x4_assert(s);
  sr = local ? &s->l : &s->r;

  /*  */
  if (s->proto == x4c_net_ip4_proto_tcp ||
      s->proto == x4c_net_ip4_proto_udp)
  {
    x4_assert(sr->port.hi == sr->port.lo);
    port = x4_bswap16(sr->port.hi);
  }

  /*  */
  range = x4_net_compare_ip(&sr->ip.lo, &sr->ip.hi, s->type);

  switch (s->type)
  {
  case x4c_net_ip_v4: 
    type = range ? x4c_ike_id_ipv4_range : x4c_ike_id_ipv4_addr;
    ipl  = 4;
    break;

  case x4c_net_ip_v6:
    type = range ? x4c_ike_id_ipv6_range : x4c_ike_id_ipv6_addr;
    ipl  = 16;
    break;

  default:
    x4_assert(0);
    return id;
  }

  /*  */
  x4_buf_append(&id, &type, 1);
  x4_buf_append(&id, &s->proto, 1);
  x4_buf_append(&id, &port, 2);
  x4_buf_append(&id, sr->ip.lo.v4, ipl);
  if (range)
    x4_buf_append(&id, sr->ip.hi.v4, ipl);

  return id;
}


/*  */
bval x4_ike_id_to_selector(const x4s_buf * id, x4s_net_selector * s, 
                           bval local)
{
  x4s_net_socket_range * sr;

  size_t     dlen;
  x4e_net_ip type;
  bval       range = bfalse;

  /*  */
  x4_assert(id && s);

  if (id->len < 4)
    return bfalse;

  sr = local ? &s->l : &s->r;

  /*  */
  switch (id->data[0])  /* type */
  {
  case x4c_ike_id_ipv4_range:  range = btrue;     /* fallthrough */
  case x4c_ike_id_ipv4_addr:   dlen = 4; 
                               type = x4c_net_ip_v4;
                               break;

  case x4c_ike_id_ipv6_range:  range = btrue;     /* fallthrough */
  case x4c_ike_id_ipv6_addr:   dlen = 8; 
                               type = x4c_net_ip_v6;
                               break;

  case x4c_ike_id_ipv4_subnet: /* will code these later */
  case x4c_ike_id_ipv6_subnet:
  default:
    return bfalse;
  }

  /*  */
  if (id->len != 4 + dlen + (range ? dlen : 0) )
    return bfalse;

  if (s->type  && s->type != type ||
      s->proto && s->proto != id->data[1])
    return bfalse;

  /*  */
  s->proto = id->data[1];
  s->type = type;

  sr->port.lo =
  sr->port.hi = x4_bswap16( *(uint16*)(id->data+2) );

  x4_memmove(sr->ip.lo.v4, id->data+4, dlen);
  x4_memmove(sr->ip.hi.v4, range ? (id->data+4+dlen) : sr->ip.lo.v4, dlen);

  return btrue;

}

/*
 *  -- local --
 */
void _hv_to_iv(x4s_ike_phase1 * s1, const uint8 * hv, uint8 * iv)
{
  size_t hlen, blen;

  x4_assert(s1 && iv);

  hlen = s1->sa.hasher->hlen;
  blen = s1->sa.cipher->blen;

  if (hlen < blen)
  {
    x4_assert(0); /* $todo - extend IV as required */
  }

  x4_memmove(iv, hv, blen);
}
