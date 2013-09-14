OBJS = ssh-smime.o
SRCS = $(OBJS,.o=.c)
CFLAGS += -Wall
LDFLAGS += -lcrypto
PROGNAME = ssh-smime

all: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROGNAME) $(OBJS)

clean:
	rm -rf $(OBJS) $(PROGNAME)

