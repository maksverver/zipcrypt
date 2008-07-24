#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fileenc.h>

#ifndef MAX_PASS
#define MAX_PASS 1024
#endif

typedef unsigned int uint32;
typedef unsigned short uint16;

#define LFH_SIGNATURE (0x04034b50)
#define LFH_SIZE (26)
struct LocalFileHeader
{
    uint16 vneeded, flags, method, mtime, mdate;
    uint32 crc, csize, dsize;
    uint16 flen, xlen;
} __attribute__((__packed__));

#define FH_SIGNATURE (0x02014b50)
#define FH_SIZE (42)
struct FileHeader
{
    uint16 vused;
    struct LocalFileHeader local;
    uint16 clen, start, iattr;
    uint32 xattr, offset;
} __attribute__((__packed__));

#define EH_SIZE (11)
struct EncHeader
{
    uint16 id, size, version, vendor;
    char strength;
    uint16 method;
}  __attribute__((__packed__));

#define CDR_SIGNATURE (0x06054b50)
#define CDR_SIZE (18)
struct CentralDirRecord
{
    uint16 disks, start, dentries, nentries;
    uint32 size, offset;
    uint16 clen;

    char *comment;
} __attribute__((__packed__));

struct File
{
    struct File *next;

    struct FileHeader header;

    char *filename;
    void *extra;
    char *comment;
};


/* Globals */
static char *password;
enum Mode { ENC, DEC } mode;
static FILE *fp_in, *fp_out;
static struct File *first_file, *last_file;


/* Prototypes */
void parse_args(int argc, char *argv[]);
void die(char *msg);
void seed_rng();
void update_crc(uint32 *crc, char *data, int len);
uint32 read_signature();
char *read_string(uint32 len);
struct File *alloc_file();
struct File *read_lfh();
struct File *read_fh();
struct CentralDirRecord *read_cdr();
void passthrough(uint32 size);
void write_lfh(struct File *file);
void write_fh(struct File *file);
void write_cdr(struct CentralDirRecord *cdr);
void append_file(struct File *file);
int merge_file(struct File *file);
void free_file(struct File *file);
int zdecrypt(struct File *file);
int zencrypt(struct File *file);


void parse_args(int argc, char *argv[])
{
    if( argc < 4 || argc > 5 ||
        (strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "-d") != 0) )
    {
        printf( "To encrypt:  %1$s -c input.zip output.zip [password]\n"
                "To decrypt:  %1$s -d input.zip output.zip [password]\n",
                basename(argv[0]) );
        exit(0);
    }


    fp_in = fopen(argv[2], "rb");
    if(fp_in == NULL)
        die("main(): failed to open input file");

    fp_out = fopen(argv[3], "wb");
    if(fp_out == NULL)
        die("main(): failed to open input file");

    mode = (strcmp(argv[1], "-c") == 0) ? ENC : DEC;
    if(argc > 4)
        password = argv[4];
    else
    {
        password = getpass("Password: ");
        if(!password)
        {
            fprintf(stdout, "Password: ");
            fflush(stdout);
            password = malloc(1 + MAX_PASS);
            if(!fgets(password, MAX_PASS, stdin))
                die("unable to read password");
            password[MAX_PASS] = '\0';
        }
    }
}

void die(char *msg)
{
    fputs(msg, stderr);
    fputs("\n", stderr);
    fflush(stderr);
    exit(1);
}

void seed_rng()
{
    FILE *fp;
    unsigned seed;

    fp = fopen("/dev/random", "rb");
    if(!fp)
        die("seed_rng(): could not open /dev/random");
    if(fread(&seed, sizeof seed, 1, fp) != 1)
        die("seed_rng(): read error");
    fclose(fp);

    srandom(seed);
}

void update_crc(uint32 *crc, char *data, int len)
{
    int n, m;
    char byte;

    for(n = 0; n < len; ++n)
    {
        byte = data[n];
        for(m = 0; m < 8; ++m)
        {
            if(byte&1)
                *crc = ((*crc^0xdb710641) >> 1) | 0x80000000;
            else
                *crc >>= 1;
            byte >>= 1;
        }
    }
}

uint32 read_signature()
{
    uint32 sig;
    if(fread(&sig, 4, 1, fp_in) != 1)
        die("read_signature(): read failed");
    return sig;
}

char *read_string(uint32 len)
{
    char *buf;

    if(len < 0)
        die("read_string(): len < 0");

    if(len == 0)
        return NULL;

    buf = malloc(len + 1);
    if(buf == NULL)
        die("read_string(): could not allocate buffer");
    if(fread(buf, len, 1, fp_in) != 1)
        die("read_string(): could not read data");
    buf[len] = '\0';

    return buf;
}

struct File *alloc_file()
{
    struct File *file;

    file = malloc(sizeof(struct File));
    if(file == NULL)
        die("alloc_file(): could not allocate struct");
    memset(file, 0, sizeof(struct File));

    return file;
}

struct File *read_lfh()
{
    struct File *file;

    file = alloc_file();

    if(fread(&file->header.local, LFH_SIZE, 1, fp_in) != 1)
        die("read_lfh(): could not read local file header");

    file->filename = read_string(file->header.local.flen);
    file->extra    = read_string(file->header.local.xlen);

    return file;
}

struct File *read_fh()
{
    struct File *file;

    file = alloc_file();

    if(fread(&file->header, FH_SIZE, 1, fp_in) != 1)
        die("read_fh(): could not read file header");

    file->filename = read_string(file->header.local.flen);
    file->extra    = read_string(file->header.local.xlen);
    file->comment  = read_string(file->header.clen);

    return file;
}

struct CentralDirRecord *read_cdr()
{
    struct CentralDirRecord *cdr;
    struct File *p;

    cdr = malloc(sizeof(struct CentralDirRecord));
    if(cdr == NULL)
        die("read_cdr(): could not allocate struct");

    if(fread(cdr, CDR_SIZE, 1, fp_in) != 1)
        die("read_cdr(): failed to read central directory record");
    cdr->comment = read_string(cdr->clen);

    cdr->offset   = (uint32)ftell(fp_out);
    cdr->size     = 0;
    cdr->nentries = 0;
    cdr->dentries = 0;
    for(p = first_file; p != NULL; p = p->next)
    {
        cdr->size     += 4 + FH_SIZE + p->header.local.flen +
                         p->header.local.xlen + p->header.clen;
        cdr->nentries += 1;
        cdr->dentries += 1;
    }

    return cdr;
}

void passthrough(uint32 size)
{
    char buffer[8192];
    int chunk_len;

    while(size > 0)
    {
        chunk_len = size < sizeof(buffer) ? size : sizeof(buffer);
        if(fread(buffer, 1, chunk_len, fp_in) != chunk_len)
            die("passthrough(): read error");
        if(fwrite(buffer, 1, chunk_len, fp_out) != chunk_len)
            die("passthrough(): write error");
        size -= chunk_len;
    }
}

void write_lfh(struct File *file)
{
    uint32 sig;

    sig = LFH_SIGNATURE;
    if( fwrite(&sig, 4, 1, fp_out) != 1 ||
        fwrite(&file->header.local, LFH_SIZE, 1, fp_out) != 1 ||
        ( file->filename &&
           fwrite(file->filename, file->header.local.flen, 1, fp_out) != 1 ) ||
        ( file->extra &&
           fwrite(file->extra, file->header.local.xlen, 1, fp_out) != 1 ) )
    {
        die("write_lfh(): write failed");
    }
}

void write_fh(struct File *file)
{
    uint32 sig;

    sig = FH_SIGNATURE;
    if( fwrite(&sig, 4, 1, fp_out) != 1 ||
        fwrite(&file->header, FH_SIZE, 1, fp_out) != 1 ||
        ( file->filename &&
           fwrite(file->filename, file->header.local.flen, 1, fp_out) != 1 ) ||
        ( file->extra &&
           fwrite(file->extra, file->header.local.xlen, 1, fp_out) != 1 ) ||
        ( file->comment &&
           fwrite(file->comment, file->header.clen, 1, fp_out) != 1 ) )
    {
        die("write_fh(): write failed");
    }
}

void write_cdr(struct CentralDirRecord *cdr)
{
    uint32 sig;

    sig = CDR_SIGNATURE;
    if( fwrite(&sig, 4, 1, fp_out) != 1 ||
        fwrite(cdr, CDR_SIZE, 1, fp_out) != 1 ||
        (cdr->comment && fwrite(cdr->comment, cdr->clen, 1, fp_out) != 1) )
    {
        die("write_cdr(): write failed");
    }
}

void append_file(struct File *file)
{
    if(!first_file)
        first_file = last_file = file;
    else
    {
        last_file->next = file;
        last_file = file;
    }
}

int merge_file(struct File *file)
{
    struct File *p;

    for(p = first_file; p != NULL; p = p->next)
    {
        if( p->header.local.flen == file->header.local.flen &&
            memcmp(p->filename, file->filename, p->header.local.flen) == 0 )
        {
            p->header.vused  = file->header.vused;
            p->header.clen   = file->header.clen;
            p->header.start  = file->header.start;
            p->header.iattr  = file->header.iattr;
            p->header.xattr  = file->header.xattr;
            p->comment       = file->comment;
            return 1;
        }
    }

    return 0;
}

void free_file(struct File *file)
{
    free(file->filename);
    free(file->extra);
    free(file->comment);
    free(file);
}

int zdecrypt(struct File *file)
{
    struct EncHeader *eh;
    fcrypt_ctx zctx;
    char salt[16], sver[2], gver[2], sauth[10], gauth[10];
    char buffer[8192];
    int file_size, chunk_size;

    eh = (struct EncHeader*)(file->extra);

    if( file->header.local.xlen != EH_SIZE ||
        eh->id != 0x9901 || eh->size != 7 ||
        eh->strength < 1 || eh->strength > 3 ||
        file->header.local.csize < 12 + SALT_LENGTH(eh->strength) )
    {
        fprintf(stderr, "Invalid data field for AES encrypted file; skipping.\n");
        return 0;
    }

    fread(salt, SALT_LENGTH(eh->strength), 1, fp_in);
    fread(sver, 2, 1, fp_in);
    if( fcrypt_init( eh->strength, password, strlen(password),
                     salt, gver, &zctx ) != 0 )
    {
        die("zdecrypt(): fcrypt_init() failed");
    }
    if(memcmp(sver, gver, 2) != 0)
        die("zdecrypt(): password verification failed");

    file_size = file->header.local.csize - 12 - SALT_LENGTH(eh->strength);
    file->header.local.csize  = file_size;
    file->header.local.method = eh->method;
    file->header.local.xlen   = 0;
    file->header.local.flags &= ~1;
    free(file->extra);
    file->extra = NULL;

    write_lfh(file);

    file->header.local.crc    = ~0;
    while(file_size > 0)
    {
        chunk_size = file_size < sizeof buffer ? file_size : sizeof buffer;
        if(fread(buffer, 1, chunk_size, fp_in) != chunk_size)
            die("zdecrypt(): read error");
        file_size -= chunk_size;
        fcrypt_decrypt(buffer, chunk_size, &zctx);
        if(fwrite(buffer, 1, chunk_size, fp_out) != chunk_size)
            die("zdecrypt(): write error");

        update_crc(&file->header.local.crc, buffer, chunk_size);
    }
    file->header.local.crc ^= ~0;

    fseek(fp_out, file->header.offset, SEEK_SET);
    write_lfh(file);
    fseek(fp_out, 0, SEEK_END);

    fcrypt_end(gauth, &zctx);

    if(fread(sauth, sizeof(sauth), 1, fp_in) != 1)
        die("zdecrypt(): read error");
    if(memcmp(sauth, gauth, sizeof(sauth)) != 0)
        die("zdecrypt(): incorrect authentication code\n");

    return 1;
}

int zencrypt(struct File *file)
{
    struct EncHeader *eh;
    fcrypt_ctx zctx;
    char salt[16], ver[2], auth[10];
    char buffer[8192];
    int n, file_size, chunk_size;

    if(file->extra)
    {
        fprintf(stderr, "Warning: file has extra data that will be removed.\n");
        free(file->extra);
    }
    file->extra = eh = malloc(sizeof(struct EncHeader));
    if(eh == NULL)
        die("zencrypt(): could not allocate struct");

    file_size = file->header.local.csize;

    eh->id       = 0x9901;
    eh->size     = 7;
    eh->version  = 2;
    eh->vendor   = 0x4541;
    eh->strength = 3;
    eh->method   = file->header.local.method;

    file->header.local.csize  = file_size + 28;
    file->header.local.method = 99;
    file->header.local.xlen   = EH_SIZE;
    file->header.local.flags |= 1;
    file->header.local.mtime  = 0;
    file->header.local.mdate  = 0;
    file->header.local.crc    = 0;

    write_lfh(file);

    for(n = 0; n < sizeof(salt); ++n)
        salt[n] = random()&255;

    if(fcrypt_init(3, password, strlen(password), salt, ver, &zctx) != 0)
        die("zencrypt(): fcrypt_init() failed");

    if( fwrite(salt, 16, 1, fp_out) != 1 ||
        fwrite(ver,   2, 1, fp_out) != 1 )
    {
        die("zencrypt(): write error");
    }

    while(file_size > 0)
    {
        chunk_size = file_size < sizeof buffer ? file_size : sizeof buffer;
        if(fread(buffer, 1, chunk_size, fp_in) != chunk_size)
            die("zencrypt(): read error");
        file_size -= chunk_size;
        fcrypt_encrypt(buffer, chunk_size, &zctx);
        if(fwrite(buffer, 1, chunk_size, fp_out) != chunk_size)
            die("zencrypt(): write error");
    }
    fcrypt_end(auth, &zctx);
    if(fwrite(auth, 10, 1, fp_out) != 1)
        die("zencrypt(): write error");

    return 1;
}

int main(int argc, char *argv[])
{
    struct File *file;
    struct CentralDirRecord *cdr;

    parse_args(argc, argv);
    seed_rng();

    uint32 sig = read_signature();
    while(sig == LFH_SIGNATURE)
    {
        file = read_lfh();
        printf("%-40s %9d bytes  ", file->filename, file->header.local.csize);
        file->header.offset = (uint32)ftell(fp_out);
        if(file->header.local.method != 99)
        {
            printf("no encryption detected\n");
            if(mode != ENC || !zencrypt(file))
            {
                write_lfh(file);
                passthrough(file->header.local.csize);
            }
        }
        else
        {
            printf("AES encrypted\n");
            if(mode != DEC || !zdecrypt(file))
            {
                write_lfh(file);
                passthrough(file->header.local.csize);
            }
        }
        append_file(file);
        sig = read_signature();
    }

    while(sig == FH_SIGNATURE)
    {
        file = read_fh();
        if(!merge_file(file))
        {
            fprintf(stderr, "invalid file header for file \"%s\" ignored\n", file->filename);
            free_file(file);
        }
        sig = read_signature();
    }
    if(sig != CDR_SIGNATURE)
        die("main(): central directory structure expected");

    cdr = read_cdr();
    for(file = first_file; file != NULL; file = file->next)
        write_fh(file);
    write_cdr(cdr);

    return 0;
}
