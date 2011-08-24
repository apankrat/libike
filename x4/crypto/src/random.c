/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: random.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/crypto/random.h"

#include <openssl/rand.h>

void x4_random(void * data, size_t dlen)
{
  RAND_bytes(data, dlen);
}
