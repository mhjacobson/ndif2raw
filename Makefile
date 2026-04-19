all: ndif2raw

clean:
	rm -f ndif2raw
	rm -f *.o
	rm -f *.a
	rm -f *.so
	rm -rf *.dSYM

ndif2raw: ndif2raw.c appledouble.c resourcefork.c logger.c
ifeq ($(shell uname), Darwin)
	$(CC) -o $@ $^ -Wno-deprecated-declarations -DNDIF2RAW_HAS_CORESERVICES -framework CoreServices
else
	$(CC) -o $@ $^
endif
