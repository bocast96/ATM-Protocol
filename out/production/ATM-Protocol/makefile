JFLAGS = -g -cp "./lib/*:."
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	Atm.java \
	Bank.java \
	
default: classes
	@echo '#!/bin/bash' > bank
	@echo java -cp `pwd`/lib/*:`pwd` Bank >> bank 
	@chmod +x bank
	@echo '#!/bin/bash' > atm
	@echo java -cp `pwd`/lib/*:`pwd` '"$@"' Atm >> atm	
	@chmod +x atm

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class atm bank *.auth ./cards/*