/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: init.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
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

