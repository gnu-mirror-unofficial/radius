if MAINTAINER_MODE

all: raddict.h radmibs.h

raddict.h: ../raddb/dictionary
	$(AWK) -f ../scripts/dict.awk ../raddb/dictionary > raddict.h

radmibs.h: ../mibs/radmibs.h.in
	$(AWK) -f ../scripts/mksnmp-h.awk ../mibs/radmibs.h.in > radmibs.h

endif
