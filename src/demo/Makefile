CFLAGS += -I../libevent_cyassl/include
LDFLAGS += -levent -lm -lpthread -L../lib/ -levent_cyassl
TARGET?=messager

all:
	$(CC) $(CFLAGS) test.c -o $(TARGET) $(LDFLAGS)
	cp $(TARGET) ./bin/
.PHONY:clean
clean:
	rm -rf *.o TARGET ./bin