CC=gcc
TARGET_APP=avd_user
CFLAGS = -ggdb3 -Wall
INC = -I ../include
LIBS = -lm
OBJS = user.o ../lib/cJSON.o

all: $(TARGET_APP)

$(TARGET_APP): $(OBJS)
	@$(CC) $(CFLAGS) $(INC) $(OBJS) -o $@ $(LIBS)
	@rm -f $(OBJS)

%.o: %.c
	@$(CC) $(INC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	@rm -f $(OBJS) $(TARGET_APP)
