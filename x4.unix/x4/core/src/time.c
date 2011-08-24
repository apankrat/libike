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
 *	$Id: time.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/core/time.h"

#include <sys/time.h>
#include <time.h>

x4t_time x4_time()
{
  return time(0);
}

x4t_msec x4_msec()
{
  static x4t_msec t0 = 0;
  struct timeval tv;
  struct timezone tz;
  x4t_msec t1;

  gettimeofday(&tv, &tz);

  t1 = 1000*tv.tv_sec + tv.tv_usec/1000;
  return t0 ? (t1 - t0) : (t0 = t1, 0);
}
