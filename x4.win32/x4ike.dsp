# Microsoft Developer Studio Project File - Name="x4ike" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=x4ike - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "x4ike.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "x4ike.mak" CFG="x4ike - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "x4ike - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "x4ike - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "x4ike - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".out/release"
# PROP Intermediate_Dir ".temp/release/x4ike"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MT /Za /W3 /GX /O2 /I "./" /I "../" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x1009 /d "NDEBUG"
# ADD RSC /l 0x1009 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "x4ike - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".out/debug"
# PROP Intermediate_Dir ".temp/debug/x4ike"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /Za /W3 /Gm /GX /ZI /Od /I "./" /I "../" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x1009 /d "_DEBUG"
# ADD RSC /l 0x1009 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "x4ike - Win32 Release"
# Name "x4ike - Win32 Debug"
# Begin Group "core"

# PROP Default_Filter ""
# Begin Group "- win32 -"

# PROP Default_Filter ""
# Begin Group "src "

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\x4\core\src\time.c
# ADD CPP /Ze
# End Source File
# End Group
# Begin Source File

SOURCE=.\x4\core\_pack1
# End Source File
# Begin Source File

SOURCE=.\x4\core\_unpack
# End Source File
# Begin Source File

SOURCE=.\x4\core\bswap.h
# End Source File
# Begin Source File

SOURCE=.\x4\core\types.h
# End Source File
# End Group
# Begin Group "src ."

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\core\src\debug.c
# End Source File
# Begin Source File

SOURCE=..\x4\core\src\memory.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\core\_pack1
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\x4\core\_unpack
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\x4\core\bswap.h
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\x4\core\debug.h
# End Source File
# Begin Source File

SOURCE=..\x4\core\macros.h
# End Source File
# Begin Source File

SOURCE=..\x4\core\memory.h
# End Source File
# Begin Source File

SOURCE=..\x4\core\stdarg.h
# End Source File
# Begin Source File

SOURCE=..\x4\core\time.h
# End Source File
# Begin Source File

SOURCE=..\x4\core\types.h
# PROP Exclude_From_Build 1
# End Source File
# End Group
# Begin Group "crypto"

# PROP Default_Filter ""
# Begin Group "src  ."

# PROP Default_Filter ""
# Begin Group "rijndael"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\x4\crypto\src\rijndael\rijndael-alg-fst.c"
# End Source File
# Begin Source File

SOURCE="..\x4\crypto\src\rijndael\rijndael-alg-fst.h"
# End Source File
# Begin Source File

SOURCE="..\x4\crypto\src\rijndael\rijndael-api-fst.c"
# End Source File
# Begin Source File

SOURCE="..\x4\crypto\src\rijndael\rijndael-api-fst.h"
# End Source File
# End Group
# Begin Group "sha2"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\crypto\src\sha2\sha2.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\sha2\sha2.h
# End Source File
# End Group
# Begin Group "tiger"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\crypto\src\tiger\sboxes.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\tiger\tiger.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\tiger\tiger.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_3des.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_aes.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_bf.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_cast.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_des.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_idea.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\cipher_rc5.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\dh.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hasher_md5.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hasher_ripemd.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hasher_sha1.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hasher_sha2.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hasher_tiger.c
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\hmac.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\init.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\misc.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\pki.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\src\random.c
# ADD CPP /Ze
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\crypto\cipher.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\dh.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\hasher.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\hmac.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\init.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\misc.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\pki.h
# End Source File
# Begin Source File

SOURCE=..\x4\crypto\random.h
# End Source File
# End Group
# Begin Group "ike"

# PROP Default_Filter ""
# Begin Group "docs"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\ike\docs\manual.txt
# End Source File
# Begin Source File

SOURCE=..\x4\ike\docs\natt.txt
# End Source File
# Begin Source File

SOURCE=..\x4\ike\docs\vids.txt
# End Source File
# Begin Source File

SOURCE="..\x4\ike\docs\walkthrough-code.txt"
# End Source File
# Begin Source File

SOURCE="..\x4\ike\docs\walkthrough-flow.txt"
# End Source File
# End Group
# Begin Group "code"

# PROP Default_Filter ""
# Begin Group "src"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\ike\src\charon.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\const.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\exchange.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\message.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\natt.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\natt.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\packet.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase1.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase1_i.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase1_i_psk.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase1_i_sig.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase2.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase2_i.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase2_r.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phasex.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\sa.c
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\utils.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\ike\src\exchange.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\isakmp.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\message.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\packet.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase1.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phase2.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\phasex.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\src\utils.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\ike\charon.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\const.h
# End Source File
# Begin Source File

SOURCE=..\x4\ike\sa.h
# End Source File
# End Group
# Begin Group "misc"

# PROP Default_Filter ""
# Begin Group "src   ."

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\misc\src\buffer.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\misc\buffer.h
# End Source File
# End Group
# Begin Group "net"

# PROP Default_Filter ""
# Begin Group "src    ."

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\x4\net\src\address.c
# ADD CPP /Ze
# End Source File
# Begin Source File

SOURCE=..\x4\net\src\selector.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\x4\net\address.h
# End Source File
# Begin Source File

SOURCE=..\x4\net\headers.h
# End Source File
# Begin Source File

SOURCE=..\x4\net\selector.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\license.txt
# End Source File
# Begin Source File

SOURCE=..\readme.txt
# End Source File
# End Target
# End Project
