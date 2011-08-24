/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: debug.h,v 1.6 2003/04/04 21:19:19 alex Exp $
 */

#ifndef _CPHL_DEBUG_H_
#define _CPHL_DEBUG_H_

/*
 *    This header defines Debug API. The methods are compliant with
 *    default ANSI C behaviour and syntax.
 *
 *      x4e_log; 
 *      x4f_log;
 *
 *      x4f_log x4_logf_set(x4f_logf);
 *      void x4_logf(x4e_log level, const char * format, ...);
 *
 *      void x4_assert(int expresssion);
 *
 *    logf is a standard logging interface, which is initialized to
 *    a void function by default.
 *
 */

#include "x4/core/types.h"
#include "x4/core/macros.h"
#include "x4/core/stdarg.h"

/*
 *  -- assert --
 */

#ifdef NDEBUG

  #define x4_assert(e)  (1)

#else  /* NDEBUG */

  #define x4_assert(e)  ( (e) ? 1 : (x4_kaput(#e,__FILE__,__LINE__), 0) )

  void x4_kaput(const char * exp, const char * file, int line);

#endif /* NDEBUG */

/*
 *  -- logf --
 */

typedef enum 
{
  x4c_l_fatal,
  x4c_l_error,
  x4c_l_warn,
  x4c_l_info,
  x4c_l_debug,
  x4c_l_trace,
} x4e_log;

typedef void (*x4f_log)(x4e_log, const char *, va_list);

/*
 *
 */
x4f_log x4_logf_set(x4f_log f);

void x4_logf(x4e_log level, const char * format, ...);
void x4_logfv(x4e_log level, const char * format, va_list);

/*
 *  misc methods & macros
 */
void x4_trace(const char * f, ...);
void x4_debug(const char * f, ...);
void x4_info(const char * f, ...);
void x4_warn(const char * f, ...);
void x4_error(const char * f, ...);

#define x4m_uint8(v)  (0xff & (uint)(v))

#endif
