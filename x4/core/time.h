/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: time.h,v 1.1.1.1 2003/03/19 17:09:18 alex Exp $
 */

#ifndef _CPHL_TIME_H_
#define _CPHL_TIME_H_

/*
 *    The header defines Time API. 
 *
 *      x4_time_t;
 *      x4_msec_t;
 *
 *      x4_time_t x4_time();
 *      x4_msec_t x4_msec();
 *
 *    x4_time_t and x4_time() follow the semantics of ANSI time_t and
 *    time().
 *
 *    x4_msec() provides millisecond accuracy for measuring time 
 *    *intervals*. It returns a number of MILLISECONDS elapsed since 
 *    certain point of time, which is normally the moment of the first 
 *    call to x4_msec. 
 */

#include "x4/core/types.h"

typedef uint32 x4t_time;
typedef uint32 x4t_msec;

x4t_time x4_time();
x4t_msec x4_msec();

#endif

