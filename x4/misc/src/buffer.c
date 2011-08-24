/*
 *	This file is a part of libike library.
 *	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/libike
 */

/*
 *	The program is distributed under terms of BSD license. 
 *	You can obtain the copy of the license by visiting:
 *
 *	http://www.opensource.org/licenses/bsd-license.php
 */

/*
 *	$Id: buffer.c,v 1.1 2003/04/04 19:56:53 alex Exp $
 */

#include "x4/misc/buffer.h"

void x4_buf_free(x4s_buf * b)
{
  x4_assert(b);

  if (b->data && b->end)
    x4_free(b->data);

  b->data = b->end = 0;
  b->len = 0;
}

void * x4_buf_resize(x4s_buf * b, size_t len)
{
  x4_assert(b);

  if (b->data && !b->end)
  {
    x4_assert(0);    /* resizing attached buf ?! */
    x4_buf_free(b); /* detach */
  }

  if (b->data + len < b->end)
  {
    b->len = len;
    /* $todo - shrink buffer if it wastes too much space */
  }
  else
  {
    uint8 * data;
    size_t  blen, nlen;

    nlen = (len < 128) ? 128 : len;

    data = x4_realloc(b->data, nlen);
    x4_assert(data);
    
    blen = b->len;

    x4_memset(data+blen, 0, nlen-blen);
    b->data = data;
    b->len  = len;
    b->end  = data+nlen;
  }

  return b->data;
}
