/*
 * SMS TPDU dessector.
 * Copyright (C) <2019>  Crs Chin<crs.chin@gmail.com>
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

#ifndef __PLAT_H
#define __PLAT_H

#include <stdarg.h>
#include <stdio.h>

#ifdef MSWIN32
 #include "mswin32/mswin32.h"
#else  /* ! MSWIN32 */

static inline int xfprintf(FILE *stream, const char *ocoding, const char *format, ...)
{
    va_list ap;
    int res;

    va_start(ap, format);
    res = vfprintf(stream, format, ap);
    va_end(ap);

    return res;
}
#endif

#endif  /* ! __PLAT_H */
