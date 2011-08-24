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
 *	$Id: random.h,v 1.2 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_CRYPTO_RANDOM_H_
#define _CPHL_CRYPTO_RANDOM_H_

/*
 *    The interface to a pseudo-random generator.
 *
 *    $note - if the pseudo-random algorithm in use requires explicit
 *            initialization (such as entropy gathering), it must be
 *            done in crypto_init() method.
 */

#include "x4/misc/buffer.h"

void x4_random(void * data, size_t dlen);

#define x4_randomb(b)  \
  ( x4_assert(b), x4_random((b)->data, (b)->len) )

#endif
