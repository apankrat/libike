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
 *	$Id: memory.h,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#ifndef _CPHL_MEMORY_H_
#define _CPHL_MEMORY_H_

/*
 *    This header defines Memory API. The methods are equivalent to
 *    respective ANSI C functions:
 *    
 *      void * x4_malloc(size_t size);
 *      void * x4_mallocz(size_t size); // the same as calloc(1, size);
 *      void * x4_realloc(void * ptr, size_t size);
 *      void   x4_free(void * ptr);
 *    
 *      void * x4_memmove(void * dest, const void * src, size_t n);
 *      void * x4_memset(void * dest, int c, size_t n);
 *      int    x4_memcmp(const void * s1, const void * s2, size_t n);
 *
 *    $note - it's recommended to explicetly (re-)declare API methods in 
 *            this header rather than to include standard <string.h> and 
 *            <malloc.h> headers. The reason being is that including 
 *            standard headers pulls a lot of extra declarations in 
 *            (including sprintf), which may inadvertently be referenced 
 *            and then linked into the code.
 *
 */

#include "x4/core/types.h"

void * x4_malloc(size_t size);
void * x4_mallocz(size_t size);
void * x4_realloc(void * ptr, size_t size);
void   x4_free(void * ptr);

void * x4_memmove(void * dest, const void * src, size_t n);
void * x4_memset(void * dest, int c, size_t n);
int    x4_memcmp(const void * s1, const void * s2, size_t n);

#endif
