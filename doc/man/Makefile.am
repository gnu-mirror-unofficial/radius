# $Id$
man_MANS=builddbm.8 radctl.8 radiusd.8\
	 radping.8 radtest.8 radzap.8\
         radgrep.1 radlast.1 raduse.1 radwho.1
CLEANFILES=$(man_MANS)

if MAINTAINER_MODE

endif

builddbm.8: builddbm.8.man
	soelim builddbm.8.man > builddbm.8

radctl.8: radctl.8.man
	soelim radctl.8.man > radctl.8

radgrep.1: radgrep.1.man
	soelim radgrep.1.man > radgrep.1

radiusd.8: radiusd.8.man
	soelim radiusd.8.man > radiusd.8

radlast.1: radlast.1.man
	soelim radlast.1.man > radlast.1

radping.8: radping.8.man
	soelim radping.8.man > radping.8

radtest.8: radtest.8.man
	soelim radtest.8.man > radtest.8

raduse.1: raduse.1.man
	soelim raduse.1.man > raduse.1

radwho.1: radwho.1.man
	soelim radwho.1.man > radwho.1 

radzap.8: radzap.8.man
	soelim radzap.8.man > radzap.8
