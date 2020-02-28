crypto_spake.o: crypto_spake.h crypto_spake.c
	gcc -c -W -Wall crypto_spake.c

crypto_spake.so: crypto_spake.o
	gcc -shared -o crypto_spake.so crypto_spake.o -lsodium

clean:
	rm -f *.o *.so
