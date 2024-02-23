#ifndef YAPLTH_H
#define YAPLTH_H

#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "dlfcn_compat.h"
#include "elftool.h"

typedef int (*yaplth_filter_t)(MapsStruct *workMap, MemElfContext *workElf,
                               uintptr_t *where, uintptr_t raw_value, uintptr_t new_value);

extern int yaplth_addHook(void *handle, const char *sym, void *hook, void **old);

extern int yaplth_removeHook(void *hook);

extern int yaplth_commitHook(yaplth_filter_t filter);

#endif // YAPLTH_H