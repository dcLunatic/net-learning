CC=g++
LDFLAGS=-lpcap
OBJS=beat catch
all:$(OBJS)
beat:beat.c beat.h
	$(CC) $(LDFLAGS) $^ -o $@
catch:catch.c catch.h
	$(CC) $(LDFLAGS) $^ -o $@
.PHONY:clean
clean:
	@rm -f $(OBJS)

