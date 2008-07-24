CFLAGS=-g -Wall -Ifileencrypt -m32

all: zipcrypt 

fileencrypt.a:
	( cd fileencrypt && \
	  make fileencrypt.a && \
	  cp fileencrypt.a ../ && \
	  make clean )

zipcrypt: fileencrypt.a zipcrypt.o
	$(CC) -m32 -o zipcrypt zipcrypt.o fileencrypt.a

clean:
	-rm zipcrypt fileencrypt.a zipcrypt.o
