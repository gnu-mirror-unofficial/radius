FORCE=--force
TEXINFOS=\
 attributes.texi\
 programs.texi\
 radgrep.texi\
 radping.texi\
 radzap.texi\
 builddbm.texi\
 radauth.texi\
 radius.texi\
 radscm.texi\
 radctl.texi\
 radlast.texi\
 radwho.texi

all: radius.info

html:
	makeinfo $(FORCE) --html radius.texi

radius.info: $(TEXINFOS) config.texi version.texi
	makeinfo $(FORCE) radius.texi

config.texi: ../texinfo/config.texi
	rm config.texi
	ln -s ../texinfo/config.texi config.texi

version.texi: ../texinfo/version.texi
	rm version.texi
	ln -s ../texinfo/version.texi version.texi