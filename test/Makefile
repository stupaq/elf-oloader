all: testaddsub testhello testvar

%.o: %.c hello.h
	gcc -m32 -o $@ -c $<

testaddsub: testaddsub.o addsub.o
	gcc -m32 -o testaddsub testaddsub.o libloader.so

testhello: testhello.o hello.o
	gcc -m32 -o testhello testhello.o libloader.so

testvar: testvar.o var.o
	gcc -m32 -o testvar testvar.o libloader.so

test: all
	./testaddsub
	./testhello
	./testvar

clean:
	rm -f *.o testaddsub testhello testvar
