/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: dh.h,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_DH_H_
#define _CPHL_DH_H_

/*
 *    The interface for performing Diffie-Hellman key exchange
 */
 
#include "x4/misc/buffer.h"

/*
 *    [dh_public] computes public DH value given an exponent (g), a modulus 
 *    (p) and a private value (x).
 *
 *    [dh_shared] computes shared DH secret provided an exponent (g),
 *    a modulus (p), private value (x), local public value (gx) and
 *    peer's public value (gy). 
 *
 *    $note - strictly speaking (gx) can be derived from (g), (p) and (x), 
 *            which makes (gx) parameter redundant. But given that (gx) would
 *            already be computed prior to calling dh_shared, it's required 
 *            to pass it as a parameter to save some CPU cycles.
 *
 *   Both methods return 0-length buf in case fo the failure.
 *
 */

x4s_buf x4_dh_public(const uint8 * g, size_t glen,
                     const uint8 * p, size_t plen,
                     const uint8 * x, size_t xlen);

x4s_buf x4_dh_shared(const uint8 * g, size_t glen,
                     const uint8 * p, size_t plen,
                     const uint8 * x, size_t xlen,
                     const uint8 * gx, size_t gxlen,
                     const uint8 * gy, size_t gylen);

/*
 *
 */
#define x4_dh_publicb(g,p,x) \
  ( x4_assert((g) && (p) && (x)), \
    x4_dh_public((g)->data, (g)->len, \
                 (p)->data, (p)->len, \
                 (x)->data, (x)->len) )

#define x4_dh_sharedb(g,p,x,gx,gy) \
  ( x4_assert((g) && (p) && (x) && (gx) && (gy)), \
    x4_dh_shared((g)->data,  (g)->len, \
                 (p)->data,  (p)->len, \
                 (x)->data,  (x)->len, \
                 (gx)->data, (gx)->len, \
                 (gy)->data, (gy)->len) )

#endif
