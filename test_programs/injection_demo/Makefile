CC = gcc
BUILDTARGETS = injectionAttack injectionAttack-badPatch injectionAttack-goodPatch
PATCHTARGETS = injectionAttack-goodPatch-patcherex injectionAttack-badPatch-patcherex

all: $(BUILDTARGETS) $(PATCHTARGETS)

$(BUILDTARGETS): % : %.o

# note, we probably want a specific artifact for injectionAttack, so we should
# be careful about rebuilding here.
$(PATCHTARGETS): injectionAttack
	python micropatch.py

$(patsubst %,%.o,$(TARGETS)): %.o : %.c
