/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: test.h,v 1.2 2003/03/26 01:56:00 alex Exp $
 */

#ifndef _CPHL_TEST_WIN32_H_
#define _CPHL_TEST_WIN32_H_

#include <windows.h>
#include <winsock.h>

/*  */
typedef SOCKET socket_t;

static socket_t _socket(int af, int type, int proto)
{
  static WSADATA wsaData = { 0 };
  
  if (! wsaData.wVersion)
    WSAStartup(0x0101, &wsaData);

  return socket(af,type,proto);
}

/*  */
#define PF_NET  AF_NET

#define socket(a,p,t) _socket(a,p,t)

#define socket_unblock(s)   ioctlsocket((s), FIONBIO, (u_long*)"\1\0\0\0");

#define socket_error()      (WSAGetLastError())

#define socket_recv(s,b,l)  recv((s),(b),(l),0)

#define socket_send(s,b,l)  send((s),(b),(l),0)

#define socket_close(s)     closesocket(s)

#endif
