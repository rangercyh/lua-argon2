SRC = luabinding.c src/argon2.c src/core.c src/blake2/blake2b.c src/thread.c src/encoding.c

CC := gcc
CFLAGS += -O3 -Wall -g -Iinclude
ifeq ($(NO_THREADS), 1)
CFLAGS += -DARGON2_NO_THREADS
else
CFLAGS += -pthread
endif

# x86 cpu-type https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
OPTTARGET ?= native
OPTTEST := $(shell $(CC) -Iinclude -Isrc -march=$(OPTTARGET) src/opt.c -c \
			-o /dev/null 2>/dev/null; echo $$?)
# Detect compatible platform
ifneq ($(OPTTEST), 0)
$(info Building without optimizations)
	SRC += src/ref.c
else
$(info Building with optimizations for $(OPTTARGET))
	CFLAGS += -march=$(OPTTARGET)
	SRC += src/opt.c
endif

LIB_NAME = argon2
SHARED := -shared -fPIC -DA2_VISCTL=1

.PHONY: all
all: $(LIB_NAME).so

$(LIB_NAME).so: $(SRC)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@

clean:
	rm -f $(LIB_NAME).so
