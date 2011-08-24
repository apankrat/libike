/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: dh.c,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#include "x4/crypto/dh.h"

#include <openssl/bn.h>
#include <openssl/dh.h>

static DH * _dh_init(const uint8 * g, size_t glen,
                     const uint8 * p, size_t plen,
                     const uint8 * x, size_t xlen)
{
  DH * dh;

  x4_assert(p && plen && g && glen && x && xlen);

  /*  */
  dh = DH_new();
  x4_assert(dh);

  /* set p */
  dh->p=BN_bin2bn(p, plen, 0);
  x4_assert(BN_is_prime(dh->p, 0,0,0,0));

  /* set g */
  dh->g=BN_bin2bn(g, glen, 0);

  /* set private part if given */
  dh->priv_key = BN_bin2bn(x, xlen, 0);

  return dh;
}

x4s_buf x4_dh_public(const uint8 * g, size_t glen,
                     const uint8 * p, size_t plen,
                     const uint8 * x, size_t xlen)
{
  DH * dh;
  x4s_buf gx = { 0 };
  
  /* init */
  dh = _dh_init(g,glen, p,plen, x,xlen);
  x4_assert(dh);

  /* generate */
  DH_generate_key(dh);

  /* cache x and gx */
  x4_buf_resize(&gx, BN_num_bytes(dh->pub_key));
  BN_bn2bin(dh->pub_key, gx.data);

  DH_free(dh);
  return gx;
}

x4s_buf x4_dh_shared(const uint8 * g, size_t glen,
                     const uint8 * p, size_t plen,
                     const uint8 * x, size_t xlen,
                     const uint8 * gx, size_t gxlen,
                     const uint8 * gy, size_t gylen)
{
  DH     * dh;
  BIGNUM * bn;
  x4s_buf gxy = { 0 };

  /*  */
  x4_assert(gx && gxlen && gy && gylen);

  /*  */
  dh = _dh_init(g,glen, p,plen, x,xlen);
  x4_assert(dh);

  dh->pub_key = BN_bin2bn(gx, gxlen, 0);
  x4_assert(dh->pub_key);

  bn = BN_bin2bn(gy, gylen, 0);
  x4_assert(bn);

  x4_buf_resize(&gxy, DH_size(dh));
  DH_compute_key(gxy.data, bn, dh);

  DH_free(dh);
  return gxy;
}
