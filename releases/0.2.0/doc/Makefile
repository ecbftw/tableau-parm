# $Id$


#XXX: Used during release only
release:
	docbook2x-man --to-stdout tableau-parm.1.docbook | sed 's/.SH DESCRIPTION/\n.SH DESCRIPTION/' > man/man1/tableau-parm.1
	cd man/man1 && gzip -9 -f tableau-parm.1
