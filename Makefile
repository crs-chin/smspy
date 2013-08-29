SMSPY_VERSION = 1.5

default:all

all:smspy-$(SMSPY_VERSION)

CFLAGS += -O2 -DNDEBUG -DVERSION=$(SMSPY_VERSION)
LDFLAGS += -s

smspy-$(SMSPY_VERSION):smspy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm smspy.o
	rm smspy-$(SMSPY_VERSION)

install:smspy-$(SMSPY_VERSION)
	install -D -m 755 smspy-$(SMSPY_VERSION) ~/bin/smspy-$(SMSPY_VERSION)
	install -D -m 755 smspy  ~/bin/smspy
	install -D -m 644 smspy.clr ~/.renderit/smspy.clr

.phony:clean install
