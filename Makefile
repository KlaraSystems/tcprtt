PROG=		tcprtt
MAN=		tcprtt.8
DPADD= ${LIBSTATS} ${LIBSBUF}
LDADD= -lstats -lsbuf

.include <bsd.prog.mk>
