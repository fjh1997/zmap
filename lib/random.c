/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "random.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "logger.h"

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

int random_bytes(void *dst, size_t n)
{
	NTSTATUS status =
	    BCryptGenRandom(NULL, (PUCHAR)dst, (ULONG)n,
			    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!BCRYPT_SUCCESS(status)) {
		log_fatal("random", "BCryptGenRandom failed: 0x%lx",
			  (unsigned long)status);
	}
	return 1;
}

#else /* UNIX */

#define RANDSRC "/dev/urandom"

int random_bytes(void *dst, size_t n)
{
	FILE *f = fopen(RANDSRC, "rb");
	if (!f) {
		log_fatal("random", "unable to read /dev/urandom: %s",
			  strerror(errno));
	}
	size_t r = fread(dst, n, 1, f);
	fclose(f);
	if (r < 1) {
		return 0;
	}
	return 1;
}

#endif /* _WIN32 */
