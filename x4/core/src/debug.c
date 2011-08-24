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
 *	$Id: debug.c,v 1.3 2003/03/26 00:22:26 alex Exp $
 */

#include "x4/core/debug.h"

#include <stdlib.h>

/*
 *  -- logf --
 */
static x4f_log _log = 0;

x4f_log x4_logf_set(x4f_log f)
{
  x4f_log r;
  return r=_log, _log=f, r;
}

void x4_logf(x4e_log level, const char * format, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, format);

    _log(level, format, m);
  }  
}

void x4_logfv(x4e_log level, const char * format, va_list m)
{
  if (_log)
    _log(level, format, m);
}

/*
 *  -- assert --
 */
void x4_kaput(const char * exp, const char * file, int line)
{
  x4_logf(x4c_l_fatal, "assert: %s in %s %u\n", exp, file, line);
  abort();
}

/*
 * -- misc --
 */
void x4_trace(const char * f, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, f);
    _log(x4c_l_trace, f, m);
  }
}

void x4_debug(const char * f, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, f);
    _log(x4c_l_debug, f, m);
  }
}

void x4_info(const char * f, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, f);
    _log(x4c_l_info, f, m);
  }
}

void x4_warn(const char * f, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, f);
    _log(x4c_l_warn, f, m);
  }
}

void x4_error(const char * f, ...)
{
  if (_log)
  {
    va_list m;
    va_start(m, f);
    _log(x4c_l_error, f, m);
  }
}
