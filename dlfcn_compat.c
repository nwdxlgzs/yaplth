/**
 * dlfcn_compat.c
 * 借助elftool.c解决安卓N上现在dlfcn.h的一些问题（未测试，理论可行，此方案将文件强行解析）
 */
#include "dlfcn_compat.h"
#include "elftool.h"
#include <sys/system_properties.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

int fake_dlclose(void *handle);

void *fake_dlopen(const char *filename, int flags);

void *fake_dlsym(void *handle, const char *name);

const char *fake_dlerror();

static int SDK_INT = -1;

int get_sdk_level() {
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    char sdk[PROP_VALUE_MAX] = {0};;
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}


int dlclose_compat(void *handle) {
    int ret;
    if (get_sdk_level() >= 24) {
        ret = fake_dlclose(handle);
    } else {
        ret = dlclose(handle);
    }
    updateProcessMaps(-1, 0);
    return ret;
}

void *dlopen_compat(const char *filename, int flags) {
    void *handle;
    if (get_sdk_level() >= 24) {
        handle = fake_dlopen(filename, flags);
    } else {
        handle = dlopen(filename, flags);
    }
    updateProcessMaps(-1, 0);
    return handle;
}

void *dlsym_compat(void *handle, const char *symbol) {
    if (get_sdk_level() >= 24) {
        return fake_dlsym(handle, symbol);
    } else {
        return dlsym(handle, symbol);
    }
}

const char *dlerror_compat() {
    if (get_sdk_level() >= 24) {
        return fake_dlerror();
    } else {
        return dlerror();
    }
}

int fake_dlclose(void *handle) {
    if (handle) {
        MemElfContext *ctx = findMemElfContext(handle, 1, 1);
        if (ctx) {
            if (ctx->useFileContent) {
                ctx->useFileContent = 0;
                if (ctx->FCdynstr) {
                    free(ctx->FCdynstr);
                    ctx->FCdynstr = NULL;
                }
                if (ctx->FCdynsym) {
                    free(ctx->FCdynsym);
                    ctx->FCdynsym = NULL;
                }
                ctx->FCnsyms = 0;
                ctx->FCbias = 0;
            }
            if (ctx->bydlopen) {
                return dlclose(handle);
            }
        } else {
            return dlclose(handle);
        }
    }
    return 0;
}


void *fake_dlopen_with_path(const char *libpath, int flags) {
    int cacheSuccess = 0;
    if (processMaps == NULL) {
        cacheSuccess = 1;
        updateProcessMaps(-1, 0);
    }
    void *handle = NULL;
    MemElfContext *ctx = NULL;
    retry:;
    for (int i = 0; i < processMaps->size; i++) {
        MapsStruct *mitem = &processMaps->maps[i];
        if (((mitem->permission & PROT_READ) && (mitem->shared == 0)) &&
            strstr(mitem->path, libpath)) {
            handle = mitem->start;
            ctx = findMemElfContext(handle, 1, 1);
            if (ctx) {
                Elf_UseFileContent(ctx);
                return handle;
            } else {
                handle = dlopen(libpath, flags);
                ctx = findMemElfContext(handle, 1, 1);
                if (ctx) {
                    ctx->bydlopen = 1;
                    Elf_UseFileContent(ctx);
                }
                return handle;
            }
        }
    }
    if (cacheSuccess == 0) {
        updateProcessMaps(-1, 0);
        cacheSuccess = 1;
        goto retry;
    }
    handle = dlopen(libpath, flags);
    ctx = findMemElfContext(handle, 1, 1);
    if (ctx) {
        ctx->bydlopen = 1;
        Elf_UseFileContent(ctx);
    }
    return handle;
}


#if defined(__LP64__)
static const char *const kSystemLibDir = "/system/lib64/";
static const char *const kOdmLibDir = "/odm/lib64/";
static const char *const kVendorLibDir = "/vendor/lib64/";
#else
static const char *const kSystemLibDir = "/system/lib/";
static const char *const kOdmLibDir = "/odm/lib/";
static const char *const kVendorLibDir = "/vendor/lib/";
#endif

void *fake_dlopen(const char *filename, int flags) {
    if (strlen(filename) > 0 && filename[0] == '/') {
        return fake_dlopen_with_path(filename, flags);
    } else {
        char buf[PATH_MAX] = {0};
        void *handle = NULL;
        //sysmtem
        strcpy(buf, kSystemLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }
        //odm
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kOdmLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }
        //vendor
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kVendorLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }
        return fake_dlopen_with_path(filename, flags);
    }
}

void *fake_dlsym(void *handle, const char *name) {
    MemElfContext *ctx = findMemElfContext(handle, 1, 1);
    if (ctx == NULL) {
        return NULL;
    }
    void *ret = Elf_SymGet(ctx, name);
    if (ret == NULL && ctx->bydlopen) {
        ret = dlsym(handle, name);
    }
    return ret;
}


const char *fake_dlerror() {
    return NULL;
}
