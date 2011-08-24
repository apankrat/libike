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
 *	$Id: bswap.h,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#ifndef _CPHL_BSWAP_H_
#define _CPHL_BSWAP_H_

/*
 *    See comments in /common/bswap.h
 */

#include "x4/core/types.h"

/*
 * Disable "'function' : no return value" warning
 */
#pragma warning (disable : 4035)

/* 
 * 
 */
__inline uint16 x4_bswap16 (uint16 v) 
         {  __asm { ror v, 8 };  return v; }

__inline uint32 x4_bswap32 (uint32 v)
         {  __asm mov eax, v  __asm bswap eax }

#define x4m_bswap16(v) ( (((v) << 8) & 0xFF00) | (((v) >> 8) & 0x00FF) )
#define x4m_bswap32(v) ( x4m_bswap16(v >> 16) | x4m_bswap16(v) << 16 )

/*
 * Restore compiler preference
 */
#pragma warning (default : 4035)

#endif
