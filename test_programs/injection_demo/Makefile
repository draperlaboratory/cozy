CC = gcc
TARGETS = injectionAttack injectionAttack-badPatch injectionAttack-goodPatch

all: $(TARGETS)

$(TARGETS): % : %.o

$(patsubst %,%.o,$(TARGETS)): %.o : %.c
