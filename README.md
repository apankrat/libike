    VERSION
    
      libike 0.9.6
    
    
    
    DESCRIPTION
    
      Libike (aka charon) is an IKE exchange management library.
    
    
    
    LICENSE
    
      Copyright (c) 2003-2011 Alex Pankratov. All rights reserved.
    
      The library is distributed under terms of BSD license. 
      You can obtain the copy of the license by visiting:
    
      http://www.opensource.org/licenses/bsd-license.php
    
    
    
    OVERVIEW
    
      Libike allows its users to engage in IKE exchanges (subject to 
      limitations listed below) as per RFC 2407, 2408, 2409.
    
      The library implements ISAKMP packet processing code, IKE 
      state management code and various miscellaneous functionality 
      such as handling of packet retransmissions, SA lifetime 
      tracking, etc.
    
      The library does NOT provide means for defining, maintaining 
      and querying security policies; it delegates this functionality 
      to the external code via the callback mechanism instead.
    
    
    
    FEATURES
    
      -- Phase 1 --
    
      * Initiator side
      * Main and Aggressive Modes
      * Preshared Key and Signature-based authentication (X.509 certs only)
      * DES, IDEA, BlowFish, RC5, 3DES, CAST, AES encryption
      * MD5, SHA1, Tiger, SHA2 hashing
      * 768-8192 MODP Oakley groups
      * Support for NAT-T drafts 1/3/5
    
      -- Phase 2 --
    
      * Initiator and Responder sides
      * PFS with groups as above
      * ESP IPsec SA (no IPCOMP or AH)
    
    
      The library implements ISAKMP packet processing, IKE exchange state 
      management and various miscellaneous functions including support for
      packet retransmissions and SA lifetime tracking.
    
      The code concerned with the cryptography is decoupled from the library 
      and is accessed via generic interface. The implementation defaults to 
      the use of OpenSSL library, yet a custom and/or hardware implementations 
      are as easily accommodated.
    
      The library does not include any networking code and makes minimal 
      assumptions about the actual packet transfer medium. This allows to
      run IKE negotiation over non-trivial carriers including raw IP, TCP, 
      custom tunneling protocols or even IPC channels. The retransmission
      logic is easily custom-tailored via the set of optional callbacks.
    
      The code is a portable C with a tiny 'glue' layer, which includes number 
      of compiler- and platform-specific definitions and methods.
    
      Currently supported platforms include Linux and Windows.  
    
    
    
    HOW TO BUILD
    
      Linux
       
       Building libike requires gcc 2.95.3 or higher;
       to build - issue the following in the root folder of the package:
    
         make -f x4.unix/Makefile
    
      Windows
       
       Building libike requires MSVC 6.0 or higher;
       to build - load x4.win32/x4.dsw and follow regular build process
    
    
    
    DOCUMENTATION
    
      Refer to contents of /docs directory for usage and design guides.
    
    
    
    VERSION HISTORY
    
      0.9.6
    
      * Refactored crypto/cipher API to extract key initialization into
        a separate step. Previously the key was expanded/instantiated once
        per every encryption/decryption call; now the initialization is
        done once per key, and its instance is then used with encryption 
        and/or decryption routines.
      * Added IDEA, CAST, RC5 and BlowFish ciphers.
      * Added Tiger, SHA2-256/384/512 hashes.
      * Modified Phase 1 code to support newly added ciphers and hashes.
    
      0.9.5
    
      * Added support for Aggressive Mode in Phase 1
      * Added 'quick code walkthrough' document, which is a bare bones guide 
        to libike's sources.
      * Refactored inbound processing code - added generalized payloads'
        sanity and consistency checks, extended generic exchange with 
        masks of expected/allowed payload types and moved some of NAT-T code 
        to a new location.
    
      0.9.4.2
    
      * Resolved a number of portability issues including the use of
        anonymous fields in structures and non-standard enum typedefs.
      * Renamed few types for a consistency
    
      0.9.4.1
    
      * Added code to run tests with RSA SIG authentication. Verified to 
        interoperate with ipsec.ssh.com and isakmp-test.ssh.fi
      * Fixed bug in IDii formating code, which caused garbage to be
        written instead of IP address
    
      0.9.4
    
      * Added support for IKE NAT traversal drafts:
          draft-ietf-ipsec-nat-t-ike-01, 
          draft-ietf-ipsec-nat-t-ike-03 and 
          draft-ietf-ipsec-nat-t-ike-05
      * Changed test code to run against 'official' SSH interop site
      * Some minor changes to the rest of the code
    
      0.9.3.1
    
      * Fixed 'exchange' context being passed instead of 'callback'
        context in few places. An artifact of a recent callback code
        cleanup.
    
      0.9.3
    
      * added manual.txt (subject to further udpates)
      * modified license.txt to refer to 'Cipherica Labs software' instead 
        of 'x4 software'.
    
      0.9.2
    
      * updated IDs of DH MODP groups as per changes made in
        draft-ietf-ipsec-ike-modp-groups-05.txt
    
      0.9.1
    
      * an initial public release
    
    
    
    TODOs
    
      * Documentation (half way there)
      * Responder mode for Phase 1
      * Ports to other platforms
      * Support for IPCOMP SAs in Phase 2
      * More interop testing
    
    
    
    REVISION
    
      $Id: readme.txt,v 1.9 2003/04/28 04:29:22 alex Exp $
