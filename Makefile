CC=gcc
CCFLAGS=-Wall -g
EXE=dnsclient

all: $(EXE)

$(EXE): $(EXE).c
	$(CC) $(CCFLAGS) $^ -o $@

clean:
	> message.log
	> dns.log
	rm -f *.o
	rm -f $(EXE)
