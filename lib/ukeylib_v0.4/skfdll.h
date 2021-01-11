#include <stdio.h>
#include <string.h>
#include <Windows.h>

#include <tchar.h>
#include "gmskf.h"
#include "skf_int.h"

int Ukey_init(char *pin);

void sign(unsigned char *in, unsigned long inLen, unsigned char *r, unsigned char *s);

unsigned long verify(unsigned char *in, unsigned long inLen, unsigned char *r, unsigned char *s);