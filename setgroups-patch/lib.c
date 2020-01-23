#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * $ gcc -Wall -fPIC -shared -o mylib.so ./lib.c -ldl
 * $ LD_PRELOAD=./mylib.so ...
 */

#include <dlfcn.h>
#include <stdio.h>
#include <grp.h>

static int (*original_setgroups) (size_t, const gid_t[]);
static int (*original_initgroups) (const char *, const gid_t);

int setgroups(size_t size, const gid_t *list) {
	// lookup the libc's setgroups() if we haven't already
	if (!original_setgroups) {
		dlerror();
		original_setgroups = dlsym(RTLD_NEXT, "setgroups");
		if (!original_setgroups) {
			fprintf(stderr, "could not find setgroups in libc");
			return -1;
		}
		dlerror();
	}

	return original_setgroups(0, NULL);
}

int initgroups(const char *user, const gid_t group) {
	// lookup the libc's setgroups() if we haven't already
	if (!original_initgroups) {
		dlerror();
		original_initgroups = dlsym(RTLD_NEXT, "initgroups");
		if (!original_initgroups) {
			fprintf(stderr, "could not find initgroups in libc");
			return -1;
		}
		dlerror();
	}

	return setgroups(0, NULL);
}
