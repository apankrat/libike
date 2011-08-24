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
 *	$Id: memory.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/core/memory.h"
#include "x4/core/debug.h"

#include <malloc.h>
#include <string.h>

/*
 *
 */
void * x4_malloc(size_t size)
{
  void * p = malloc(size);
  x4_assert(p);
  return p;
}

void * x4_mallocz(size_t size)
{
  return calloc(1, size);
}

void * x4_realloc(void * ptr, size_t size)
{
  return realloc(ptr, size);
}

void x4_free(void * ptr)
{
  free(ptr);
}

/*
 *
 */
void * x4_memmove(void * dest, const void * src, size_t n)
{
  return memmove(dest, src, n);
}

void * x4_memset(void * dest, int c, size_t n)
{
  return memset(dest, c, n);
}

int x4_memcmp(const void * s1, const void * s2, size_t n)
{
  return memcmp(s1, s2, n);
}
