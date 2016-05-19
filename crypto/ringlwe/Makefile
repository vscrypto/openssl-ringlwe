#
# crypto/ringlwe/Makefile
#

DIR=	ringlwe
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG= -g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=ringlwetest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ringlwe_key.c ringlwe_kex.c rlwe_rand_openssl_aes.c ringlwe_err.c FFT/FFT_1024_40961.c FFT/FFT_2048_17633281.c FFT/FFT_433_35507.c FFT/FFT_739_47297.c FFT/FFT_1024_40961.c FFT/FFT_2048_8816641.c FFT/FFT_512_25601.c  FFT/FFT_821_49261.c FFT/FFT_256_15361.c FFT/FFT_541_41117.c FFT/FFT_1024_8816641.c FFT/FFT_337_32353.c FFT/FFT_631_44171.c FFT/FFT_1024_17633281.c

LIBOBJ=	ringlwe_key.o ringlwe_kex.o rlwe_rand_openssl_aes.o ringlwe_err.o FFT/FFT_1024_40961.o FFT/FFT_2048_17633281.o FFT/FFT_433_35507.o FFT/FFT_739_47297.o FFT/FFT_1024_40961.o FFT/FFT_2048_8816641.o FFT/FFT_512_25601.o  FFT/FFT_821_49261.o FFT/FFT_256_15361.o FFT/FFT_541_41117.o FFT/FFT_1024_8816641.o FFT/FFT_337_32353.o FFT/FFT_631_44171.o FFT/FFT_1024_17633281.o

SRC= $(LIBSRC)

EXHEADER= ringlwe.h
HEADER=	ringlwe_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

FFT_1024_17633281.o: FFT/FFT_1024_17633281.c FFT/FFT_constants.h
FFT_1024_17633281.o: FFT/FFT_includes.h FFT_1024_17633281.c
FFT_1024_40961.o: FFT/FFT_1024_40961.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_1024_40961.o: FFT_1024_40961.c
FFT_1024_8816641.o: FFT/FFT_1024_8816641.c FFT/FFT_constants.h
FFT_1024_8816641.o: FFT/FFT_includes.h FFT_1024_8816641.c
FFT_2048_17633281.o: FFT/FFT_2048_17633281.c FFT/FFT_constants.h
FFT_2048_17633281.o: FFT/FFT_includes.h FFT_2048_17633281.c
FFT_2048_8816641.o: FFT/FFT_2048_8816641.c FFT/FFT_constants.h
FFT_2048_8816641.o: FFT/FFT_includes.h FFT_2048_8816641.c
FFT_256_15361.o: FFT/FFT_256_15361.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_256_15361.o: FFT_256_15361.c
FFT_337_32353.o: FFT/FFT_337_32353.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_337_32353.o: FFT_337_32353.c
FFT_433_35507.o: FFT/FFT_433_35507.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_433_35507.o: FFT_433_35507.c
FFT_512_25601.o: FFT/FFT_512_25601.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_512_25601.o: FFT_512_25601.c
FFT_541_41117.o: FFT/FFT_541_41117.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_541_41117.o: FFT_541_41117.c
FFT_631_44171.o: FFT/FFT_631_44171.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_631_44171.o: FFT_631_44171.c
FFT_739_47297.o: FFT/FFT_739_47297.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_739_47297.o: FFT_739_47297.c
FFT_821_49261.o: FFT/FFT_821_49261.c FFT/FFT_constants.h FFT/FFT_includes.h
FFT_821_49261.o: FFT_821_49261.c
ringlwe_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ringlwe_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ringlwe_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ringlwe_err.o: ../../include/openssl/opensslconf.h
ringlwe_err.o: ../../include/openssl/opensslv.h
ringlwe_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/ringlwe.h
ringlwe_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ringlwe_err.o: ../../include/openssl/symhacks.h ringlwe_err.c
ringlwe_kex.o: ../../include/openssl/aes.h ../../include/openssl/bio.h
ringlwe_kex.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
ringlwe_kex.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
ringlwe_kex.o: ../../include/openssl/lhash.h
ringlwe_kex.o: ../../include/openssl/opensslconf.h
ringlwe_kex.o: ../../include/openssl/opensslv.h
ringlwe_kex.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
ringlwe_kex.o: ../../include/openssl/ringlwe.h
ringlwe_kex.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ringlwe_kex.o: ../../include/openssl/symhacks.h FFT/FFT_includes.h
ringlwe_kex.o: ringlwe_consts.h ringlwe_kex.c ringlwe_kex.h ringlwe_locl.h
ringlwe_kex.o: rlwe_rand_openssl_aes.h
ringlwe_key.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
ringlwe_key.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ringlwe_key.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ringlwe_key.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ringlwe_key.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
ringlwe_key.o: ../../include/openssl/opensslconf.h
ringlwe_key.o: ../../include/openssl/opensslv.h
ringlwe_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
ringlwe_key.o: ../../include/openssl/ringlwe.h
ringlwe_key.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ringlwe_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ringlwe_key.o: FFT/FFT_includes.h ringlwe_consts.h ringlwe_kex.h ringlwe_key.c
ringlwe_key.o: ringlwe_locl.h rlwe_rand_openssl_aes.h
rlwe_rand_openssl_aes.o: ../../include/openssl/aes.h
rlwe_rand_openssl_aes.o: ../../include/openssl/e_os2.h
rlwe_rand_openssl_aes.o: ../../include/openssl/opensslconf.h
rlwe_rand_openssl_aes.o: ../../include/openssl/ossl_typ.h
rlwe_rand_openssl_aes.o: ../../include/openssl/rand.h rlwe_rand_openssl_aes.c
rlwe_rand_openssl_aes.o: rlwe_rand_openssl_aes.h
