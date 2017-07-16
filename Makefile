all: overflowfix.c
	gcc -m32 -fPIC -Wall -shared overflowfix.c -o ovfix.so -ldl

clean:
	$(RM) ovfix.so