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
 *	$Id: hasher_tiger.c,v 1.1 2003/04/27 21:37:37 alex Exp $
 */

#include "x4/crypto/hasher.h"
#include "x4/core/memory.h"

#include "tiger/tiger.h"

/*  */
static void _tiger_update(x4s_hasher * h, const void * data, size_t dlen)
{
  x4s_buf * b;

  x4_assert(h && h->update == _tiger_update);

  b = (x4s_buf*)(h+1);
  x4_buf_append(b, data, dlen);
}

/*  */
static void _tiger_complete(x4s_hasher * h, uint8 * hval)
{
  x4s_buf * b;

  x4_assert(h && h->complete == _tiger_complete);

  b = (x4s_buf*)(h+1);

  if (hval)
    _tiger(b->data, b->len, hval);  

  x4_buf_free(b);
  x4_free(h);
}

/*  */
static void _tiger_process(const void * data, size_t dlen, uint8 * hval)
{
  _tiger(data, dlen, hval);
}

/*  */
static x4s_hasher * _tiger_instance()
{
  x4s_hasher * h;

  h = x4_mallocz(sizeof(x4s_hasher) + sizeof(x4s_buf));
  if (! h)
    return 0;

  h->api = x4v_tiger;
  h->update = _tiger_update;
  h->complete = _tiger_complete;

  return h;
}

/*
 *
 */
static x4s_hasher_alg ha_tiger = { 24, 64, _tiger_process, _tiger_instance };
x4s_hasher_alg * x4v_tiger = &ha_tiger;
