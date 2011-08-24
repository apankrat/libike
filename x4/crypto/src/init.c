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
 *	$Id: init.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/crypto/init.h"

#include <openssl/rand.h>
#include <openssl/pem.h>

/*  */
bval x4_crypto_init()
{
  SSLeay_add_all_algorithms();
  RAND_poll();
  return btrue;
}

void x4_crypto_term()
{
}

