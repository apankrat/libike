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
 *	$Id: hmac.h,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#ifndef _CPHL_CRYPTO_HMAC_H_
#define _CPHL_CRYPTO_HMAC_H_

/*
 *  HMAC algorithm as defined in RFC 2104.
 */

#include "x4/crypto/hasher.h"

x4s_hasher * x4_hmac(x4s_hasher_alg * hapi, const void * key, size_t klen, size_t hlen);

#define x4_hmacb(ha, kb) \
  ( x4_assert(kb), x4_hmac(ha, (kb)->data, (kb)->len, 0) )

#define x4_hmacb2(ha, kb, hlen) \
  ( x4_assert(kb), hmac(ha, (kb)->data, (kb)->len, (hlen)) )

#endif
