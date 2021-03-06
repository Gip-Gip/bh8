/*
Bit-Hider 8 (bh8) encryption software, provided under the ISC license:

Copyright (c) 2016, Charles "Gip-Gip" Thompson

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    false,
    true
} bool;

enum {
    one,
    two,
    three,
    four,
    five,
    six,
    seven,
    eight
};

enum {
    none,
    err_unknown,
    err_noargs,
    err_helpGiven,
    err_noin,
    err_nopass,
    err_innotreal,
    err_willnot,
    err_outcant,
    err_fwrite,
    err_fread,
    err_randerr,
    err_norand,
    err_alloc
};

#define BYTEMV 255

#define MSG_SPASH "\n\
bh8 v2.2016!\n\
============\n\
\n\
"
#define MSG_HELP "\n\
USAGE:\n\
\n\
bh8 -i [infile] (optional arguments)\n\
\n\
ARGUMENTS:\n\
\n\
-d = decrypt the infile\n\
-h = show this message and exit\n\
-l = use /dev/random, if available(very slow)\n\
-o [outfile] = specify a outfile\n\
-p [password] = specify the password to use\n\
-v = give pointless(debugging) messages\n\
-y = overwrite files without asking\n\
\n\
"
#define MSG_DONE "\n\
=====\n\
DONE!\n\
"
#define MSG_GIVEPASS "Password:"
#define MSG_DECRYPTING "Decrypting!\n"
#define MSG_NOIN "ERROR: No input file given!\n"
#define MSG_INNOTREAL "ERROR: Specified infile does not exist!\n"
#define MSG_ALLOCERR "ERROR: Could not allocate memory\n"
#define MSG_CANNOTWTI "ERROR: You cannot write to infile(yet)!\n"
#define MSG_OUTEXISTS "Outfile already exits! Do you wish to overwrite?(y/n)\n"
#define MSG_OUTCANT "ERROR: Cannot write to out file!\n"
#define MSG_WILLNOT "'y' not given! Exiting\n"
#define MSG_TOD " Will be decrypted to "
#define MSG_TOE " Will be encrypted to "
#define MSG_FREAD "ERROR: Could not read infile!\n"
#define MSG_FWRITE "ERROR: Could not write to outfile!\n"
#define MSG_RANDERR "ERROR: Could not read random device!\n"
#define MSG_LONGRAND "WARNING: -l given! Prepare to wait forever!\n"
#define MSG_URAND "Using /dev/urandom\n"
#define MSG_NORAND "ERROR: No random device detected!\n"
#define MSG_BASE8EQU "The base8 password is "

#define ARG_HELP "-h"
#define ARG_IN "-i"
#define ARG_PASS "-p"
#define ARG_OUT "-o"
#define ARG_DECRYPT "-d"
#define ARG_VERBOSE "-v"
#define ARG_OVERWRITE "-y"
#define ARG_LONGRAND "-l"

#define FILEEXT ".bh8"

FILE *inFile = NULL;
FILE *outFile = NULL;
FILE *randomFile = NULL;

bool getBit(char byte, int bit)
{
    switch(bit)
    {
        case one:
            return byte & 1;
            break;
        case two:
            return byte & 2;
            break;
        case three:
            return byte & 4;
            break;
        case four:
            return byte & 8;
            break;
        case five:
            return byte & 16;
            break;
        case six:
            return byte & 32;
            break;
        case seven:
            return byte & 64;
            break;
        case eight:
            return byte & 128;
            break;
    }
    return 0;
}

char *strToBase8(char *str)
{
    char *ret = calloc(strlen(str) * 3 + 1, sizeof(char));
    char *retchar = ret;

    if(ret == NULL) return NULL;

    while(*str)
    {
        *retchar = (*str & 1) + (*str & 2) + (*str & 4) + '0';
        *(retchar + 1) =
            ((*str & 8)/8) + ((*str & 16)/8) + ((*str & 32)/8) + '0';
        *(retchar + 2) =
            ((*str & 32)/32) + ((*str & 64)/32) + ((*str & 128)/32) + '0';
        retchar += 3;
        str++;
    }

    return ret;
}

char *fmakes(FILE *__file)
{
    char *rt = calloc(1, sizeof(char));
    int rtsz = 0;
    char bf = 0;

    while(!feof(__file) && fread(&bf, sizeof(char), sizeof(bf), __file) && bf != '\n')
    {
        rt = realloc(rt, rtsz + 2);
        rt[rtsz] = bf;
        rt[rtsz + 1] = 0;
        rtsz = strlen(rt);
    }

    return rt;
}

void closeAll()
{
    if(outFile != NULL) fclose(outFile);
    if(inFile != NULL) fclose(inFile);
}

char power2(int by)
{
    char result = 2;
    if(by == 0) return 1;
    by--;
    while(by--)
    {
        result *= 2;
    }
    return result;
}

int main(int argc, char *argv[])
{
    int argn = argc;
    char *in = NULL;
    char *out = NULL;
    char *password = NULL;
    bool decrypt = false;
    bool verbose = false;
    bool overwrite = false;
    bool longrand = false;
    char inBuff = 0;
    char outBuff = 0;
    char place = 0;
    int passchar = 0;
    int loopn = 0;

    printf(MSG_SPASH);

    if(argc <= 1)
    {
        printf("%s%s", MSG_HELP, MSG_DONE);
        return err_noargs;
    }

    while((argn--) > 1)
    {
        if(!strcmp(argv[argn], ARG_HELP))
        {
            printf("%s%s", MSG_HELP, MSG_DONE);
            return err_helpGiven;
        }

        else if(!strcmp(argv[argn - 1], ARG_IN))
        {
            in = argv[argn];
        }

        else if(!strcmp(argv[argn - 1], ARG_PASS))
        {
            password = argv[argn];
        }

        else if(!strcmp(argv[argn - 1], ARG_OUT))
        {
            out = argv[argn];
        }

        else if(!strcmp(argv[argn], ARG_DECRYPT))
        {
            decrypt = true;
        }

        else if(!strcmp(argv[argn], ARG_VERBOSE))
        {
            verbose = true;
        }

        else if(!strcmp(argv[argn], ARG_OVERWRITE))
        {
            overwrite = true;
        }

        else if(!strcmp(argv[argn], ARG_LONGRAND))
        {
            longrand = true;
        }
    }

    if(in == NULL)
    {
        printf("%s%s%s", MSG_NOIN, MSG_HELP, MSG_DONE);
        return err_noin;
    }

    if(password == NULL)
    {
        printf(MSG_GIVEPASS);
        password = fmakes(stdin);
    }

    if(!(password = strToBase8(password)))
    {
        printf("%s%s", MSG_ALLOCERR, MSG_DONE);
        return err_alloc;
    }

    if(verbose == true) printf("%s%s\n", MSG_BASE8EQU, password);

    if(out == NULL)
    {
        out = calloc(
            strlen(in) + strlen(FILEEXT) + sizeof(char), sizeof(char));

        if(out == NULL)
        {
            printf("%s%s", MSG_ALLOCERR, MSG_DONE);
            return err_alloc;
        }

        strcat(out, in);
        strcat(out, FILEEXT);
    }

    if(!strcmp(out, in))
    {
        printf("%s%s", MSG_CANNOTWTI, MSG_DONE);
        return 0;
    }

    if(!(inFile = fopen(in, "rb")))
    {
        printf("%s%s", MSG_INNOTREAL, MSG_DONE);
        return err_innotreal;
    }

    if((outFile = fopen(out, "rb")) && overwrite == false)
    {
        printf(MSG_OUTEXISTS);
        scanf("%c", &overwrite);
        if(overwrite != 'y' && overwrite != 'Y')
        {
            printf("%s%s", MSG_WILLNOT, MSG_DONE);
            return err_willnot;
        }
    }

    if(!(outFile = fopen(out, "wb")))
    {
        printf("%s%s", MSG_OUTCANT, MSG_DONE);
        return err_outcant;
    }

    fseek(inFile, 0, SEEK_SET);
    fseek(outFile, 0, SEEK_SET);

    if(decrypt == true)
    {
        printf("%s%s%s\n", in, MSG_TOD, out);
        while(!feof(inFile))
        {
            if(fread(&inBuff, sizeof(inBuff), 1, inFile) != 1 && !feof(inFile))
            {
                printf("%s%s", MSG_FREAD, MSG_DONE);
                closeAll();
                return err_fread;
            }

            place = power2(loopn);

            if(getBit(inBuff, *(password + passchar) - '0')) outBuff += place;

            passchar ++;

            if(!(*(password + passchar)))
            {
                passchar = 0;
            }

            loopn ++;

            if(loopn > eight)
            {
                if(fwrite(&outBuff, sizeof(outBuff), 1, outFile) != 1)
                {
                    printf("%s%s", MSG_FWRITE, MSG_DONE);
                    closeAll();
                    return err_fwrite;
                }
                loopn = 0;
                outBuff = 0;
            }
        }
    }

    else
    {
        if(longrand == true && (randomFile = fopen("/dev/random", "rb")))
        {
            printf(MSG_LONGRAND);
        }
        else if((randomFile = fopen("/dev/urandom", "rb")))
        {
            if(verbose == true) printf(MSG_URAND);
        }
        else
        {
            printf("%s%s", MSG_NORAND, MSG_DONE);
        return err_norand;
        }

        printf("%s%s%s\n", in, MSG_TOE, out);
        loopn = eight + 1;
        while(!feof(inFile))
        {
            if(loopn > eight)
            {
                if(fread(&inBuff, sizeof(inBuff), 1, inFile) != 1 &&
                    !feof(inFile))
                {
                    printf("%s%s", MSG_FREAD, MSG_DONE);
                    closeAll();
                    return err_fwrite;
                }
                loopn = 0;
            }

            if(randomFile == NULL) outBuff = rand();
            else if(fread(&outBuff, sizeof(char), 1, randomFile) != 1)
            {
                printf("%s%s", MSG_RANDERR, MSG_DONE);
                closeAll();
                return err_randerr;
            }

            place = power2(*(password + passchar) - '0');

            if(getBit(inBuff, loopn)) outBuff |= place;
            else outBuff &= ~place;

            if(fwrite(&outBuff, sizeof(outBuff), 1, outFile) != 1)
            {
                printf("%s%s", MSG_FWRITE, MSG_DONE);
                closeAll();
                return err_fwrite;
            }

            loopn ++;
            passchar ++;

            if(!(*(password + passchar)))
            {
                passchar = 0;
            }
        }
    }

    closeAll();

    printf(MSG_DONE);
    return none;
}
