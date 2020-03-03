CC  := gcc
CXX := g++

CFLAGS ?= -ggdb3 -Wall -fPIC $(INCLUDE)
CFLAGS ?= $(CFLAGS) -std=c++11
LDFLAGS += $(addprefix -l, $(LIBS))

SRCS ?= $(wildcard *.c)
OBJS ?= $(addprefix obj/, $(patsubst %.c, %.o, $(SRCS)))

RECURSIVE_TARGETS ?= all clean

SHARED_LIB_TARGETS := $(filter %.so, $(TARGETS))
STATIC_LIB_TARGETS := $(filter %.a, $(TARGETS))
OTHER_TARGETS := $(filter-out %.so, $(filter-out %.a, $(TARGETS)))

MAKEPATH ?= `basename "$(PWD)"`

LOG_PREFIX := "$(shell tput setaf 7)[$(MAKEPATH)]$(shell tput sgr0)$(shell tput setaf 2)"
LOG_SUFFIX := "$(shell tput sgr0)"

all:: $(TARGETS)

clean::
	@for target in $(TARGETS); do \
		echo $(LOG_PREFIX) Cleaning $$target $(LOG_SUFFIX); \
	done
	@rm -rf $(TARGETS) obj build

.PHONY: all clean

obj/%.o: %.c $(PREREQS)
	@echo $(LOG_PREFIX) Compiling $< $(LOG_SUFFIX)
	@mkdir -p obj
	@$(CC) $(CFLAGS) -o $@ -c $<

$(SHARED_LIB_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $@ $(LOG_SUFFIX)
	@$(CC) -shared $(LIBS) -o $@ $^

$(STATIC_LIB_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $2 $(LOG_SUFFIX)
	@ar rs $@ $^

$(OTHER_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $@ $(LOG_SUFFIX)
	@$(CC) -o $@ $^ $(CUSTOM_LIBS) $(LIBS) $(INCLUDE)

-include $(OBJS:.o=.d)

$(RECURSIVE_TARGETS)::
	@for dir in $(DIRS); do \
		$(MAKE) -C $$dir --no-print-directory $@ MAKEPATH="$(ROOT)/$$dir"; \
	done
