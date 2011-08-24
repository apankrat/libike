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
 *	$Id: test.h,v 1.3 2003/04/04 21:20:26 alex Exp $
 */

#ifndef _CPHL_TEST_LINUX_H_
#define _CPHL_TEST_LINUX_H_

#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*  */
typedef int socket_t;

/*  */
#define socket_unblock(s)   fcntl((s), F_SETFL, O_NONBLOCK)

#define socket_error()      (errno)

#define socket_recv(s,b,l)  read((s),(b),(l))

#define socket_send(s,b,l)  write((s),(b),(l))

#define socket_close(s)     close(s)
#endif
