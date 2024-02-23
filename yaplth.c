/**
 * yaplth: Yet Another Procedure Linkage Table Hook
 * 这个一个基于PLT-GOT的hook框架
 */
#include "yaplth.h"

int yaplth_addHook(void *handle, const char *sym, void *hook, void **old) {
    if (handle == NULL || sym == NULL || hook == NULL) {
        return -1;
    }
    MemElfContext *ctx = findMemElfContext(handle, 1, 1);
    if (ctx == NULL) {
        return -2;
    }
    ptrList pl = {0};
    Elf_findPLT(ctx, sym, &pl);
    if (pl.size == 0) {
        return -4;
    }
    void *where_sym_addr = pl.ptrs[pl.size - 1];
    free(pl.ptrs);
    void *sym_addr = *((void **) where_sym_addr);
    if (sym_addr == NULL) {
        return -3;
    }
    if (old) {
        *old = sym_addr;
    }
    pthread_mutex_lock(&ctx->mutex);
    PtrBakup *hooks_start = ctx->hooks;
    PtrBakup *hooks_head = hooks_start;
    while (hooks_head) {
        if (hooks_head->where == where_sym_addr ||
            hooks_head->raw_value == sym_addr ||
            hooks_head->new_value == sym_addr) {
            pthread_mutex_unlock(&ctx->mutex);
            return -4;
        }
        hooks_head = hooks_head->next;
    }
    //添加记录
    PtrBakup *hook_bak = (PtrBakup *) malloc(sizeof(PtrBakup));
    hook_bak->where = where_sym_addr;
    hook_bak->raw_value = sym_addr;
    hook_bak->new_value = hook;
    hook_bak->worked = 0;
    hook_bak->next = ctx->hooks;
    ctx->hooks = hook_bak;
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

static inline char *PageStart(char *addr) {
    uintptr_t ptr = (uintptr_t) addr;
    ptr &= PAGE_MASK;
    return (char *) ptr;
}

int yaplth_removeHook(void *hook) {
    if (hook == NULL) {
        return -1;
    }
    //遍历全部MemElfContext
    for (int i = 0; i < memElfContextList->size; i++) {
        MemElfContext *ctx = &memElfContextList->ctxs[i];
        pthread_mutex_lock(&ctx->mutex);
        PtrBakup *hooks_start = ctx->hooks;
        PtrBakup *hooks_head = hooks_start;
        PtrBakup *hooks_pre = NULL;
        while (hooks_head) {
            if (hooks_head->new_value == hook) {
                MapsStruct *maps = getModuleMaps(-1, ctx->base);
                if (maps && hooks_head->worked) {
                    int prot = maps->permission;
                    uintptr_t page_start = 0;
                    uintptr_t *where = (uintptr_t *) hooks_head->where;
                    uintptr_t raw_value = (uintptr_t) hooks_head->raw_value;
                    int ok;
                    if (!(prot & PROT_WRITE)) {
                        page_start = (uintptr_t) PageStart((char *) where);
                        maps->permission = PROT_READ | PROT_WRITE | PROT_EXEC;
                        ok = !mprotect((void *) page_start, PAGE_SIZE, maps->permission);
                    } else {
                        ok = 1;
                    }
                    if (ok) {
                        *where = raw_value;
                    }
                    if (!(prot & PROT_WRITE)) {
                        maps->permission = prot;
                        mprotect((void *) page_start, PAGE_SIZE, maps->permission);//我可不管你能不能改回去
                    }
                }
                if (hooks_pre) {
                    hooks_pre->next = hooks_head->next;
                } else {
                    ctx->hooks = hooks_head->next;
                }
                free(hooks_head);
                break;
            }
            hooks_pre = hooks_head;
            hooks_head = hooks_head->next;
        }
        pthread_mutex_unlock(&ctx->mutex);
    }

    return 0;
}

static int yaplth_defaultFilter(MapsStruct *workMap, MemElfContext *workElf,
                                uintptr_t *where, uintptr_t raw_value, uintptr_t new_value) {
    uintptr_t cur = *where;
    return cur == raw_value;
}

int yaplth_commitHook(yaplth_filter_t filter) {
    if (filter == NULL) {
        filter = yaplth_defaultFilter;
    }
    for (int i = 0; i < memElfContextList->size; i++) {
        MemElfContext *ctx = &memElfContextList->ctxs[i];
        pthread_mutex_lock(&ctx->mutex);
        PtrBakup *hooks_start = ctx->hooks;
        if (hooks_start) {
            MapsStruct *maps = getModuleMaps(-1, ctx->base);
            if (maps) {
                PtrBakup *hooks_head = hooks_start;
                while (hooks_head) {
                    int prot = maps->permission;
                    uintptr_t page_start = 0;
                    uintptr_t *where = (uintptr_t *) hooks_head->where;
                    int ok;
                    int worked = hooks_head->worked;
                    if (!worked) {
                        if (!(prot & PROT_WRITE)) {
                            page_start = (uintptr_t) PageStart((char *) where);
                            maps->permission = PROT_READ | PROT_WRITE | PROT_EXEC;
                            ok = !mprotect((void *) page_start, PAGE_SIZE, maps->permission);
                        } else {
                            ok = 1;
                        }
                    } else {
                        ok = 0;
                    }
                    if (ok) {
                        uintptr_t raw_value = (uintptr_t) hooks_head->raw_value;
                        uintptr_t new_value = (uintptr_t) hooks_head->new_value;
                        if (filter(maps, ctx, where, raw_value, new_value)) {
                            *where = new_value;
                            hooks_head->worked = 1;
                        }
                    }
                    if (!worked) {
                        if (!(prot & PROT_WRITE)) {
                            maps->permission = prot;
                            mprotect((void *) page_start, PAGE_SIZE, maps->permission);//我可不管你能不能改回去
                        }
                    }
                    hooks_head = hooks_head->next;
                }
            }
        }
        pthread_mutex_unlock(&ctx->mutex);
    }
    return 0;
}
