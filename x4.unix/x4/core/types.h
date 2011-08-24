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
 *	$Id: types.h,v 1.3 2003/04/04 21:24:53 alex Exp $
 */

#ifndef _CPHL_TYPES_H_
#define _CPHL_TYPES_H_

/*
 *    See comments in /common/types.h
 */

#include "x4/core/macros.h"
#include <sys/types.h>

typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned long   uint32;

typedef enum
{
  bfalse,
  btrue
} bval;

#endif
