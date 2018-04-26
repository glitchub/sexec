default: sexec

CFLAGS=-std=gnu99 -Wall -Werror -lcap
sexec: sexec.c

clean:;rm -f sexec	
