#ifndef EXCEPT_H
#define EXCEPT_H

#include <setjmp.h>

extern jmp_buf except_buf;

#define try		if (!setjmp(except_buf))
#define catch		else
#define throw		longjmp(except_buf, 1)

#endif
