#
#	This file is a part of libike library.
#	Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
#
#	http://swapped.cc/libike
#

#
#	The library is distributed under terms of BSD license. 
#	You can obtain the copy of the license by visiting:
#
#	http://www.opensource.org/licenses/bsd-license.php
#

#
#	$Id: Makefile,v 1.6 2003/04/27 22:44:52 alex Exp $
#

INCLUDES = -I./x4.unix -I./ -Ix4/crypto/rijndael
LIBS     = -lcrypto

WARNINGS = -Werror -Wwrite-strings 
OPT = -O3
DEBUG = -ggdb
CFLAGS = \
        $(DEBUG) $(OPT) $(WARNINGS) $(OS_FLAGS) \
        $(INCLUDES)

PROG=   charon
OBJS=   \
	x4.unix/x4/core/src/time.o \
	x4/core/src/debug.o \
	x4/core/src/memory.o \
	\
	x4/net/src/address.o \
	x4/net/src/selector.o \
	\
	x4/misc/src/buffer.o \
	\
	x4/crypto/src/cipher_3des.o \
	x4/crypto/src/cipher_aes.o \
	x4/crypto/src/cipher_des.o \
	x4/crypto/src/cipher_bf.o \
	x4/crypto/src/cipher_cast.o \
	x4/crypto/src/cipher_idea.o \
	x4/crypto/src/cipher_rc5.o \
	x4/crypto/src/dh.o \
	x4/crypto/src/hasher_md5.o \
	x4/crypto/src/hasher_sha1.o \
	x4/crypto/src/hasher_sha2.o \
	x4/crypto/src/hasher_ripemd.o \
	x4/crypto/src/hasher_tiger.o \
	x4/crypto/src/hmac.o \
	x4/crypto/src/init.o \
	x4/crypto/src/misc.o \
	x4/crypto/src/pki.o \
	x4/crypto/src/random.o \
	x4/crypto/src/rijndael/rijndael-alg-fst.o \
	x4/crypto/src/rijndael/rijndael-api-fst.o \
	x4/crypto/src/sha2/sha2.o \
	x4/crypto/src/tiger/sboxes.o \
	x4/crypto/src/tiger/tiger.o \
	\
	x4/ike/src/charon.o \
	x4/ike/src/const.o \
	x4/ike/src/exchange.o \
	x4/ike/src/message.o \
	x4/ike/src/natt.o \
	x4/ike/src/packet.o \
	x4/ike/src/phase1.o \
	x4/ike/src/phase1_i.o \
	x4/ike/src/phase1_i_psk.o \
	x4/ike/src/phase1_i_sig.o \
	x4/ike/src/phase2.o \
	x4/ike/src/phase2_i.o \
	x4/ike/src/phase2_r.o \
	x4/ike/src/phasex.o \
	x4/ike/src/sa.o \
	x4/ike/src/utils.o \
	\
	x4/test/test.psk.o

DEPS= $(OBJS:%.o=%.d)

.PHONY: all clean

all: $(PROG)
	@echo build complete

clean:
	@rm -rf $(PROG) \
	  `find . -name "*.o" -print` \
	  `find . -name "*.d" -print`
	@echo clean up complete

$(PROG): $(OBJS)
	@echo l: $(PROG)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	@echo c: $<
	@$(CC) $(CFLAGS) -o $@ -c $<

%.d: %.c
	@echo d: $<
	@$(CC) $(CFLAGS) -MM $< | sed "s|$(*F).o:|$@ $*.o:|" > $@
# 	the above sed magic is by stephen@dino.dnsalias.com

-include $(DEPS)
