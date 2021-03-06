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
 *	$Id: bswap.h,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#ifndef _CPHL_BSWAP_H_
#define _CPHL_BSWAP_H_

/*
 *    See comments in /common/bswap.h
 */

#include <byteswap.h>

#define x4_bswap16(v) bswap_16(v)
#define x4_bswap32(v) bswap_32(v)

#define x4m_bswap16(v) ( (((v) << 8) & 0xFF00) | (((v) >> 8) & 0x00FF) )
#define x4m_bswap32(v) ( x4m_bswap16(v >> 16) | x4m_bswap16(v) << 16 )

#endif
