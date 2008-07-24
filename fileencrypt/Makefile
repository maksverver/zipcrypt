CFLAGS=-O2 -m32
OBJECTS=aescrypt.o aeskey.o aestab.o fileenc.o hmac.o prng.o pwd2key.o sha1.o

all: fileencrypt.a
	
fileencrypt.a: $(OBJECTS)
	ar -r fileencrypt.a $(OBJECTS)

clean:
	-rm $(OBJECTS) fileencrypt.a

