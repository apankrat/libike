/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: time.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
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
