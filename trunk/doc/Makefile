# $Id$

BUILD_FILES=$(BUILD_DOC)/man/man1/tableau-parm.1.gz

default: $(BUILD_FILES)

$(BUILD_DOC)/man/man1/tableau-parm.1.gz: man/man1/tableau-parm.1.gz
	mkdir -p $(BUILD_DOC)/man/man1
	cp man/man1/tableau-parm.1.gz $@

install:
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	ln -sf $(DOC_PREFIX)/man/man1/*  $(MAN_PREFIX)/man1


#XXX: Used during release only
release:
	docbook2x-man --to-stdout tableau-parm.1.docbook > man/man1/tableau-parm.1
	cd man/man1 && gzip -9 -f tableau-parm.1
