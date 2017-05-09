.c.o:
	gcc -g -c $?

hiahia:hiahia.o
	gcc -g -o hiahia hiahia.o   -lpcap
