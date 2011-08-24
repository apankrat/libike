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
 *  x4_bswapxx() functions convert values between network (LSB) and 
 *  host byte order. For Intel platforms these methods will be untrivial,
 *  while for little-endian platforms they will return original values.
 *
 *  Function prototypes are as follows -
 *  
 *    uint16 x4_bswap16(uint16);
 *    uint32 x4_bswap32(uint32);
 *
 *  Macros are -
 *
 *    x4m_bswap16(v)
 *    x4m_bswap32(v)
 *
 */

  $todo - implement for the platform in use

#endif
