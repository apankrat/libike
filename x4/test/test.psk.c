/*
 *    Copyright (c) 2003, Cipherica Labs. All rights reserved.
 *    See enclosed license.txt for redistribution information.
 *
 *    $Id: test.psk.c,v 1.1 2003/04/27 22:44:52 alex Exp $
 */

#include "x4/core/time.h"
#include "x4/net/headers.h"
#include "x4/crypto/init.h"
#include "x4/crypto/random.h"
#include "x4/crypto/hmac.h"
#include "x4/crypto/pki.h"
#include "x4/ike/charon.h"

#include "test.h"
#include <stdio.h>

/* ipsec.ssh.com *
#define PEER  "195.20.116.69"

/* isakmp-test.ssh.fi */
#define PEER  "195.20.116.71"


/*
 *  -- Charon interop test --
 *  
 *  Go to https://ipsec.ssh.com, SSH IPSec Interoperability Test Site,
 *  and configure it to use preshared secret authentication with 'test' 
 *  (w/o quotes) secret, negotiate tunnel between 10.0.0.1 and 192.168.10.1
 *  peer with SA as below.
 *  
 *  Once ready, run the test and verify it completes both phases of the 
 *  negotiation. Also try running it in NAT-T mode, by commenting out
 *  the code in line 373.
 *
 */


/*
 *  Globals
 */
struct sockaddr_in l  = { PF_INET, x4m_bswap16(500), 0 };
struct sockaddr_in r  = { PF_INET, x4m_bswap16(500), 0 };

socket_t s = 0;
bval     floated = bfalse;

/*
 * log callback
 */
void on_logf(x4e_log l, const char * format, va_list m)
{
  static x4t_time t0 = 0;

  if (! t0) 
    t0 = x4_time();

  printf("%3u.%03u %u: ", x4_time()-t0, x4_msec()%1000, l);
  vprintf(format, m);
}

/*
 *  phase 1 callbacks
 */
void on_ph1_initiated(void * ctx, x4s_ike_phase1 * s1)
{ 
  *(void**)ctx = s1;
  x4_info("ph1_initiated(%08x, %08x)\n", ctx, s1);
}

void on_ph1_completed(void * ctx)
{ 
  x4_info("### ph1_completed(%08x)\n", ctx);

  {
    /* initiate phase 2 */
    x4s_ike_config2 ph2 =
    {
      x4c_ike_tr_esp_3des,
      x4c_ike_a2e_tunnel,
      x4c_ike_a2a_hmac_md5_96,
      0,
      0,
      
      32,
      x4c_ike_a1g_modp_1024,
      /*
      { 0 },
      { 1234, 5678 }
      */
    };

    x4s_net_selector * sel = &ph2.selector;

    sel->proto = 0; //x4c_net_ip4_proto_icmp;
    sel->type  = x4c_net_ip_v4;

    
    sel->l.ip.lo.x =
    sel->l.ip.hi.x = inet_addr("10.0.0.108");

    sel->r.ip.lo.x =
    sel->r.ip.hi.x = inet_addr("192.168.10.1");

    x4_charon_init2(&ph2, *(void**)ctx);
    /**/
  }
}

void on_ph1_disposed(void * ctx)
{ 
  x4_info("ph1_disposed(%08x)\n", ctx);
}

void on_ph1_sa_used(void * ctx, uint bytes)
{
  x4_info("sa_used(%08x, %u)\n", ctx, bytes);
}

bval on_ph1_validate(void * ctx, const x4s_buf * b, x4e_ike_validate w)
{ 
  x4_info("ph1_validate(%08x, %u)\n", ctx, w);
  return btrue;
}

bval on_ph1_send(void * ctx, const x4s_buf * pkt)
{ 
  static uint8 buf[65536];
  uint8 * data;
  uint    dlen;

  x4_info("<< ph1 (%08x, %u)\n", ctx, pkt->len);
  
  if (floated)
  {
    data = x4_memset(buf, 0, 4);
    x4_memmove(buf+4, pkt->data, pkt->len);
    dlen = pkt->len+4;
  }
  else
  {
    data = pkt->data;
    dlen = pkt->len;
  }

  socket_send(s, data, dlen);
  return btrue;
}

uint on_ph1_resend(void * ctx, uint seqno, uint retry, bval dejavu)
{
  x4_info("ph1_resend(%08x, %u, %u%s)\n", ctx, seqno, retry, dejavu ? ", dejavu" : "");
  return seqno < 0xff ? retry < 3 ? 1 : 0 : 0;
}

void on_ph1_float(void * ctx, x4s_net_link * link, bval behind_nat)
{
  x4_info("ph1_float(%08x, %08x, %u)\n", ctx, link, behind_nat);

  if (link)
  {
    socket_close(s);

    l.sin_port = x4m_bswap16(4500);
    r.sin_port = x4m_bswap16(4500);
  
    /* create */
    s = socket(PF_INET, SOCK_DGRAM, 0);

    /* unblock */
    socket_unblock(s);

    /* bind */
    bind(s, (struct sockaddr*)&l, sizeof(l));

    /* connect */
    connect(s, (struct sockaddr*)&r, sizeof(r));

    /* get IP we are bound to */
    link->l.port = 4500;
    link->r.port = 4500;
  }
}

x4s_buf on_ph1_get_psk(void * ctx)
{ 
  x4s_buf r = { (void*)"test", 0, 4 };
  x4_info("ph1_get_psk(%08x)\n", ctx);
  return r;
}

x4s_buf on_ph1_get_cert(void * ctx)
{ 
  x4s_buf r = x4_load_pem_x509_cert("x4/test/" PEER ".cert" );
  x4_info("ph1_get_cert(%08x)\n", ctx);
  return r;
}

x4s_buf on_ph1_get_prikey(void * ctx)
{ 
  x4s_buf r = x4_load_pem_rsa_prikey("x4/test/" PEER ".pkey", "password");
  x4_info("ph1_get_prikey(%08x)\n", ctx);
  return r;
}

x4s_buf on_ph1_get_pubkey(void * ctx, const x4s_buf * idr)
{ 
  x4s_buf r = { 0 };
  x4_info("ph1_get_pubkey(%08x)\n", ctx);
  return r;
}

/*
 *  phase 2 callbacks
 */
void on_ph2_initiated(void * ctx, x4s_ike_phase2 * s2)
{
  x4_info("ph2_initiated(%08x, %08x)\n", ctx, s2);
}

void * on_ph2_responded(void * ctx1, x4s_ike_phase2 * s2)
{  
  x4_info("ph2_responded(%08x, %08x)\n", ctx1, s2);
  return (void*)0x12345678;
}

void on_ph2_completed(void * ctx, const x4s_ike_keys2 * k)
{
  x4_info("### ph2_completed(%08x) %08x %08x\n", ctx, k->spi_l, k->spi_r);
}

void on_ph2_disposed(void * ctx)
{
  x4_info("ph2_disposed(%08x)\n", ctx);
}

uint32 on_ph2_get_spi()
{
  uint32 spi;
  x4_random(&spi,4);
  x4_info("ph2_getspi() %08x\n", spi);
  return spi;
}

bval on_ph2_validate(void * ctx, const x4s_ike_config2 * sa)
{
  x4_info("ph2_validate(%08x, sa)\n", ctx);
  x4_info("  cipher : %u\n"
         "  encaps : %u\n"
         "    auth : %u\n"
         "  ipcomp : %u\n"
         "   kbits : %u\n"
         "    nlen : %u\n"
         "   group : %u\n"
         "  life.t : %u\n"
         "  life.b : %u\n",
         sa->cipher, sa->encaps, sa->auth,
         sa->ipcomp, sa->kbits, sa->nlen,
         sa->group, sa->lifetime.seconds, sa->lifetime.kbytes);

  return btrue;
}

uint on_ph2_resend(void * ctx, uint seqno, uint retry, bval dejavu)
{
  x4_info("ph2_resend(%08x, %u, %u%s)\n", ctx, seqno, retry, dejavu ? ", dejavu" : "");
  return 2;
}

bval on_ph2_send(void * ctx, const x4s_buf * pkt)
{
  static uint8 buf[65536];
  uint8 * data;
  uint    dlen;

  x4_info("<< ph2 (%08x, %u)\n", ctx, pkt->len);
  
  if (floated)
  {
    data = x4_memset(buf, 0, 4);
    x4_memmove(buf+4, pkt->data, pkt->len);
    dlen = pkt->len+4;
  }
  else
  {
    data = pkt->data;
    dlen = pkt->len;
  }

  socket_send(s, data, dlen);
  return btrue;
}

void hmm();

int main(int argc, char ** argv)
{
  x4s_ike_config c = 
  {
    on_ph1_initiated,
    on_ph1_completed,
    on_ph1_disposed,
    on_ph1_sa_used,
    on_ph1_validate,
    on_ph1_send,
    0, //on_ph1_resend,
    on_ph1_float,
    on_ph1_get_psk,
    on_ph1_get_cert,
    on_ph1_get_prikey,
    on_ph1_get_pubkey,

    on_ph2_initiated,
    on_ph2_responded,
    on_ph2_completed,
    on_ph2_disposed,
    on_ph2_validate,
    on_ph2_send,
    0, //on_ph2_resend,
    on_ph2_get_spi,
    
    bfalse,
    bfalse,
    32,
    0xffff
  };

  x4s_ike_config1 ph1 = { 0 };
  void * ph1context;

  uint32 a;
  int alen;

  /*  */
  x4_logf_set(on_logf);

  /*  */
  x4_crypto_init();

  /* decide who's the peer */
  a = inet_addr(PEER);
  x4_memmove(&r.sin_addr, &a, 4);

  /* create */
  s = socket(PF_INET, SOCK_DGRAM, 0);

  /* unblock */
  socket_unblock(s);

  /* bind */
  bind(s, (struct sockaddr*)&l, sizeof(l));

  /* connect */
  connect(s, (struct sockaddr*)&r, sizeof(r));

  /* get IP we are bound to */
  alen = sizeof(l);
  getsockname(s, (struct sockaddr*)&l, &alen);

  /*  */
  x4_charon_init(&c);

  /*  */
//ph1.aggressive = btrue;
  ph1.hash   = x4c_ike_a1h_tiger; //ripemd; //sha1;
  ph1.cipher = x4c_ike_a1e_des_cbc;
  ph1.group  = x4c_ike_a1g_modp_1024;
  ph1.auth   = x4c_ike_a1a_preshared; //rsa_sig;
//ph1.kbits  = 40;
  ph1.nlen   = 16;
  ph1.userdata = &ph1context;

  ph1.link.type = x4c_net_ip_v4;
  x4_memmove(ph1.link.l.ip.v4, &l.sin_addr, 4);
  ph1.link.l.port = 500;

  ph1.link.type = x4c_net_ip_v4;
  x4_memmove(ph1.link.r.ip.v4, &r.sin_addr, 4);
  ph1.link.r.port = 500;

  ph1.natt = 0xff;
  
  x4_charon_init1(&ph1);

  for (;;)
  {
    struct timeval tv = { 0, 500000 };  /* 50 msec */
    fd_set fdr, fde;

    FD_ZERO(&fdr); FD_SET(s, &fdr);
    FD_ZERO(&fde); FD_SET(s, &fde);
    
    if (select(s+1, &fdr, 0, &fde, &tv) < 0)
    {
      x4_info("select() failed w %u\n", socket_error());
      break;
    }

    if (FD_ISSET(s, &fdr))
    {
      static char buf[65540];
      int  n;

      n = socket_recv(s, buf, sizeof(buf));
      if (n > 0)
      {
        x4s_buf pkt = { 0 };
      
        x4_info(">> %u\n", n);
        x4_buf_attach(&pkt, buf, n);  
        x4_charon_recv(&ph1.link, &pkt);
      }
    }

    if (FD_ISSET(s, &fde))
    {
      x4_info("socket error %u\n", socket_error());
      break;
    }
     
    x4_charon_tick();
  }

  return 0;
}
