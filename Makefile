SMSPY_VERSION = 1.8

default:all

all:smspy-$(SMSPY_VERSION) smspy-mswin32-$(SMSPY_VERSION).exe

CFLAGS += -O2 -DNDEBUG -DVERSION=$(SMSPY_VERSION)

# Flags for Linux
LNX_CFLAGS := -m64
LNX_SRC := smspy.c 	plat.h
LNX_OBJ := smspy.o

# Flags for MSWin32
WIN_CFLAGS = -DMSWIN32
WIN_SRC := smspy.c \
		plat.h \
		mswin32/mswin32.c \
		mswin32/mswin32.h \
		mswin32/iconv/include/iconv.h
WIN_OBJ := smspy-win32.o \
		mswin32/mswin32.o
WIN_LIB := mswin32/iconv/lib/libiconv.dll.a

LDFLAGS += -s

WIN_CC = i686-w64-mingw32-gcc

$(LNX_OBJ):$(LNX_SRC)
	$(CC) -c $(CFLAGS) $(LNX_CFLAGS) $< -o $@

smspy-$(SMSPY_VERSION):$(LNX_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@


$(WIN_OBJ):$(WIN_SRC)
smspy-win32.o:smspy.c
	$(WIN_CC) -c $(CFLAGS) $(WIN_CFLAGS) $< -o $@
mswin32/%.o:mswin32/%.c
	$(WIN_CC) -c $(CFLAGS) $(WIN_CFLAGS) $< -o $@

smspy-mswin32-$(SMSPY_VERSION).exe:$(WIN_OBJ) $(WIN_LIB)
	$(WIN_CC) $(LDFLAGS) $^ -o $@

clean:
	@rm -f smspy-$(SMSPY_VERSION) smspy-mswin32-$(SMSPY_VERSION).exe
	@rm -f $(LNX_OBJ) $(WIN_OBJ)

install:smspy-$(SMSPY_VERSION)
	install -D -m 755 smspy-$(SMSPY_VERSION) ~/bin/smspy-$(SMSPY_VERSION)
	install -D -m 755 smspy  ~/bin/smspy
	install -D -m 644 smspy.clr ~/.renderit/smspy.clr

.phony:clean install
