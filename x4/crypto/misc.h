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
 *	$Id: misc.h,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_CRYPTO_MISC_H_
#define _CPHL_CRYPTO_MISC_H_

#include "x4/misc/buffer.h"

/*
 *  Auxiliary structure and methods for convinient 
 *  handling of DH exchanges
 *
 */
x4m_struct( x4s_dh_data )
{
  x4s_buf  g, p, x;        /* DH exponent, modulus and private our value */
  x4s_buf  gx, gy;         /* local (gxi) and remote (gyi) public values */
  x4s_buf  gxy;            /* shared secret                              */
};

/*  */
void x4_dh_data_free(x4s_dh_data *);

/*
 *  dh_initiate() initializes 'x' to the random sequence of dh.p->len bytes
 *  and computes public 'gxi' value. It expects 'g' and 'p' to be properly 
 *  initialized prior to the call.
 *
 *  in:  g, p
 *  out: x, gxi
 */
void x4_dh_initiate(x4s_dh_data * dh);

/*  dh_complete() computes shared DH secret.
 *
 *  in:  g, p, x, gxi, gyi
 *  out: gxy
 */
bval x4_dh_complete(x4s_dh_data * dh);

#endif
