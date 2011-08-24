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
 *	$Id: macros.h,v 1.4 2003/04/04 21:17:13 alex Exp $
 */

#ifndef _CPHL_MACROS_H_
#define _CPHL_MACROS_H_

/*
 *  The following macros enforce unified structure, enum and
 *  union typedef'ing notation.
 */

/*
 *  -- struct -- 
 */
#define x4m_declare_struct(T) \
  typedef struct T##_tag T;

#define x4m_define_struct(T)  \
  struct T##_tag

#define x4m_struct(T)   \
  x4m_declare_struct(T) \
  x4m_define_struct(T)

/*
 *  -- union -- 
 */
#define x4m_declare_union(U) \
  typedef union U##_tag U;

#define x4m_define_union(U)  \
  union U##_tag

#define x4m_union(U)   \
  x4m_declare_union(U) \
  x4m_define_union(U)

#endif


