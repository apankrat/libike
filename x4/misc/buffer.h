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
 *	$Id: buffer.h,v 1.1 2003/04/04 19:56:53 alex Exp $
 */

#ifndef _CPHL_MISC_buf_H_
#define _CPHL_MISC_buf_H_

/*
 *  General purpose byte buffer (x4s_buf) and byte buffer parser (buf_walker).
 */

#include "x4/core/types.h"
#include "x4/core/memory.h"
#include "x4/core/debug.h"

/*    
 *  buf is comprised of the pointer to the datablock (data), datablock 
 *  length (len) and the actual end of the datablock pointer (end). 
 *  [x4s_buf.end] also serves as an ownership indicator; it's non-zero if 
 *  x4s_buf owns the data and is 0 otherwise. Non-owning x4s_buf is further 
 *  referred to as 'attached x4s_buf'.
 *  
 *  $note - functions that accept [data, len] pair of parameters are 
 *          normally paired with their xxxb() macro equivalents that accept
 *          x4s_buf pointer instead. For example:
 *
 *            x4_buf_assign(x4s_buf * b, const void * data, size_t len) 
 *          has
 *            x4_buf_assignb(x4s_buf * b, const x4s_buf * src) 
 *
 */

x4m_struct( x4s_buf )
{
  uint8 * data;
  uint8 * end;
  size_t  len;
};

/* -- core operations -- */
#define x4_buf_init(b) \
  { x4_assert(b); (b)->data = (b)->end = 0; (b)->len = 0; }

void   x4_buf_free(x4s_buf *);
void * x4_buf_resize(x4s_buf *, size_t);

/* -- x4s_buf manipulation -- */
#define x4_buf_swap(dst, src) \
  { x4s_buf temp; x4_assert((dst) && (src)); \
    temp = *dst; *dst = *src; *src = temp; }

#define x4_buf_attach(b, p, l) \
  (void*)( x4_assert(b), x4_buf_free(b), \
           (b)->len = (l), (b)->data = (uint8*)(p) )

#define x4_buf_assign(b, p, l)  \
  (void*)( x4_assert(b), x4_buf_resize((b), (l)), \
           (p) ? x4_memmove((b)->data, (p), (l)) : (b)->data )

#define x4_buf_append(b, p, l) \
  (void*)( x4_assert(b), x4_buf_resize((b), (b)->len + (l)), \
           (p) ? x4_memmove((b)->data + (b)->len - (l), (p), (l)) \
               : x4_memset((b)->data + (b)->len - (l), 0, (l)) )

#define x4_buf_prepend(b, p, l) \
  (void*)( x4_assert(b), x4_buf_resize((b), (b)->len  + (l)), \
           x4_memmove((b)->data + (l), (b)->data, (b)->len - (l)), \
           (p) ? x4_memmove((b)->data, (p), (l)) \
               : x4_memset((b)->data, 0, (l)) )

#define x4_buf_compare(b1, b2) \
  (x4_assert((b1) && (b2)), \
   (b1)->len != (b2)->len ? (b1)->len-(b2)->len \
                          : x4_memcmp((b1)->data, (b2)->data, (b1)->len))                

/* 
 *  -- x4s_buf/x4s_buf equivalents -- 
 */
#define x4_buf_attachb(dst, src) \
  ( x4_assert(src), x4_buf_attach((dst), (src)->data, (src)->len) )

#define x4_buf_assignb(dst, src) \
  ( x4_assert(src), x4_buf_assign((dst), (src)->data, (src)->len) )

#define x4_buf_appendb(dst, src) \
  ( x4_assert(src), x4_buf_append((dst), (src)->data, (src)->len) )

#define x4_buf_prependb(dst, src) \
  ( x4_assert(src), x4_buf_prepend((dst), (src)->data, (src)->len) )

/*
 *  General purpose x4s_buf iterator
 *
 *  x4s_buf_walker holds a pointer to a x4s_buf and current offset 
 *  within the buffer. buf_walker's methods are effectively an API 
 *  for traversing (parsing) a target buffer.
 *
 */
x4m_struct( x4s_buf_walker )
{
  x4s_buf  * b;
  size_t    cur;
};

#define x4_walker_init(w, buf)  \
  { x4_assert(w); (w)->b = (buf); (w)->cur = 0; }

#define x4_walker_size(w)  \
  ( x4_assert((w) && (w)->b), (w)->b->len - (w)->cur )

#define x4_walker_pos(w) \
  ( x4_assert((w) && (w)->b), (w)->cur )

#define x4_walker_rewind(w)  \
  { x4_assert((w) && (w)->b); (w)->cur = 0; }

#define x4_walker_data(w)  \
  (void*)( x4_assert((w) && (w)->b), (w)->b->data + (w)->cur )

#define x4_walker_fetch(w, n) \
  (void*)( x4_assert((w) && (w)->b), \
           (w)->b->len < n + (w)->cur ? 0 : \
           (w)->b->data - n + ((w)->cur += n) )

#endif
