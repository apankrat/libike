/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: time.c,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#include "x4/core/time.h"

#include <windows.h>
#include <time.h>

x4t_time x4_time()
{
  return time(0);
}

x4t_msec x4_msec()
{
  static x4t_msec t0 = 0;
  return t0 ? (GetTickCount() - t0) : 
              (t0 = GetTickCount(), 0);
}
