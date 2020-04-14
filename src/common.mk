CC  := gcc
CXX := g++

CFLAGS ?= -ggdb3 -fPIC -Wall -Wno-misleading-indentation $(INCLUDE)
CXXFLAGS ?= $(CFLAGS) -std=c++11

SRCS ?= $(wildcard *.c) $(addprefix $(LIB_DIR), $(CUSTOM_LIBS))
OBJS ?= $(patsubst %.c, %.o, $(wildcard *.c)) $(patsubst %.c, %.o, $(CUSTOM_LIBS))


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
	@rm -rf $(TARGETS) *.o build

.PHONY: all clean

%.o: %.c $(PREREQS)
	@echo $(LOG_PREFIX) Compiling $< $(LOG_SUFFIX)
	@$(CC) $(CFLAGS) -c $< $(addprefix $(LIB_DIR)/, $(CUSTOM_LIBS))

$(SHARED_LIB_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $@ $(LOG_SUFFIX)
	@$(CC) -shared $(LIBS) -o $@ $^

$(STATIC_LIB_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $2 $(LOG_SUFFIX)
	@ar rs $@ $^

$(OTHER_TARGETS): $(OBJS)
	@echo $(LOG_PREFIX) Linking $@ $(LOG_SUFFIX)
	@$(CC) -o $@ $^ $(LIBS) $(INCLUDE)

-include $(OBJS:.o=.d)

$(RECURSIVE_TARGETS)::
	@for dir in $(DIRS); do \
		$(MAKE) -C $$dir --no-print-directory $@ MAKEPATH="$(ROOT)/$$dir"; \
	done
