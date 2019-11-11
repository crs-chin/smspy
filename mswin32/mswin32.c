/*
 * SMS TPDU dessector.
 * Copyright (C) <2018>  Crs Chin<crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "mswin32.h"
#include "iconv/include/iconv.h"

#define INIT_STRING_LEN 100

static char *convert_encoding(const char *text, int len,
                              const char *dstcoding,
                              const char *srccoding)
{
    const char *inbuf;
    char *outbuf, *str;
    size_t in, sz, out, res;
    iconv_t ct;

    if(len < 0)
        in = strlen(text);
    else
        in = (size_t)len;
    sz = out = len = in;

    str = (char *)malloc(sz + 1);
    if(! str)
        return NULL;

    ct = iconv_open(dstcoding, srccoding);
    if(ct == (iconv_t)-1)  {
        printf("Failed encoding convert from %s to %s\n", srccoding, dstcoding);
        free(str);
        return NULL;
    }

    for(inbuf = text, outbuf = str;;)  {
        res = iconv(ct, &inbuf, &in, &outbuf, &out);
        if(res == -1)  {
            if(errno == E2BIG)  {
                out += len;
                sz += len;
                str = (char *)realloc(str, sz + 1);
                if(! str)  {
                    printf("OOM converting encoding!\n");
                    break;
                }
                outbuf = str + sz - out;
                continue;
            }
        }
        break;
    }

    iconv_close(ct);
    str[sz - out] = '\0';
    return str;
}

static int vasprintf(char **strp, const char *fmt, va_list _ap)
{
    va_list ap;
    char *buf;
    size_t len = INIT_STRING_LEN * 10;
    int res;

    if(! strp || ! fmt || ! (buf = (char *)malloc(len)))
        return -1;

    va_copy(ap, _ap);
    do {
        res = vsnprintf(buf, len, fmt, ap);
        if(res >= len) {
            free(buf);

            if(! (buf = (char *)malloc(len + INIT_STRING_LEN))) {
                res = -1;
                break;
            }

            len += INIT_STRING_LEN;
            va_end(ap);
            va_copy(ap, _ap);
            continue;
        }
    } while(0);
    va_end(ap);

    *strp = buf;
    return res;
}

int xfprintf(FILE *stream, const char *format, ...)
{
    va_list ap;
    char *src = NULL;
    int res;

    wchar_t *dest = NULL;
    int dest_sz;

    va_start(ap, format);
    do{
        if((res = vasprintf(&src, format, ap)) < 0)
            break;

        if(! (dest = (wchar_t *)convert_encoding(src, -1, XLOCALE, "UTF-8")))
            break;

        /* dest_sz = (res + 1) * sizeof(wchar_t); */
        /* if(! (dest = (wchar_t *)malloc(dest_sz))) { */
        /*     res = -1; */
        /*     break; */
        /* } */

        /* if((res = MultiByteToWideChar(CP_ACP, 0, src, -1, dest, res + 1)) < 0) { */
        /*     res = -1; */
        /*     break; */
        /* } */

        res = fwprintf(stream, L"%s",  dest);
    }while(0);
    va_end(ap);

    if(src)
        free(src);
    if(dest)
        free(dest);
    return res;
}


