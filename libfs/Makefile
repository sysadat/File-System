# Target library
lib  := libfs.a
objs := fs.o disk.o

CC     := gcc
STATIC := ar
STATIC += rcs

CFLAGS := -Wall -Werror -Wextra

ifneq ($(V),1)
Q = @
endif

all: $(lib)

deps := $(patsubst %.o, %.d, $(objs))
-include $(deps)
DEPFLAGS = -MMD -MF $(@:.o=.d)

%.a: $(objs)
	@echo "CC $@"
	$(Q) $(STATIC) $@ $^

%.o: %.c
	@echo "CC $@"
	$(Q) $(CC) $(CFLAGS) -c -o $@ $< $(DEPFLAGS)

clean:
	@echo "clean"
	$(Q) rm -f $(lib) $(objs) $(deps)
