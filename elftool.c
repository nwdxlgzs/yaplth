/**
 * elftool.c
 * 提供一套Elf解析方案
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "elftool.h"

pthread_mutex_t memElfContextList_Mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t processMaps_Mutex = PTHREAD_MUTEX_INITIALIZER;

void Elf_Open(MemElfContext *ctx) {
    if (ctx == NULL || ctx->base == NULL || ctx->opened) return;
    ctx->opened = 1;
    if (ctx->valid)return;
    if (0 != memcmp(ctx->base, ELFMAG, SELFMAG)) return;
#if defined(__LP64__)
    if (ELFCLASS64 != ctx->base[EI_CLASS]) return;
#else
    if (ELFCLASS32 != ctx->base[EI_CLASS]) return;
#endif
    if (ELFDATA2LSB != ctx->base[EI_DATA]) return;
    if (EV_CURRENT != ctx->base[EI_VERSION]) return;
    ctx->header = (ElfW(Ehdr) *) ctx->base;
    if (ET_EXEC != ctx->header->e_type && ET_DYN != ctx->header->e_type) return;
#if defined(__arm__)
    if (EM_ARM != ctx->header->e_machine) return;
#elif defined(__aarch64__)
    if (EM_AARCH64 != ctx->header->e_machine) return;
#elif defined(__i386__)
    if (EM_386 != ctx->header->e_machine) return;
#elif defined(__x86_64__)
    if (EM_X86_64 != ctx->header->e_machine) return;
#else
    return;
#endif
    if (EV_CURRENT != ctx->header->e_version) return;
    ctx->phdr = (ElfW(Phdr) *) (ctx->base + ctx->header->e_phoff);
    char *ph_off = (char *) ctx->phdr;
    for (int i = 0; i < ctx->header->e_phnum; i++, ph_off += ctx->header->e_phentsize) {
        ElfW(Phdr) *ph = (ElfW(Phdr) *) ph_off;
        if (ph->p_type == PT_LOAD && ph->p_offset == 0) {
            if (ctx->base >= (char *) ph->p_vaddr) {
                ctx->bias = ctx->base - ph->p_vaddr;
            }
        } else if (ph->p_type == PT_DYNAMIC) {
            ctx->dynamic = (ElfW(Dyn) *) (ph->p_vaddr);
            ctx->dynamic_size = ph->p_memsz;
        }
    }
    if (!ctx->dynamic || !ctx->bias) return;
    ctx->dynamic = (ElfW(Dyn) *) (ctx->bias + (ElfW(Addr)) ctx->dynamic);
    for (ElfW(Dyn) *dynamic = ctx->dynamic,
                 *dynamic_end = ctx->dynamic + (ctx->dynamic_size / sizeof(dynamic[0]));
         dynamic < dynamic_end; ++dynamic) {
        switch (dynamic->d_tag) {
            case DT_NULL:
                dynamic = dynamic_end;
                break;
            case DT_STRTAB: {
                ctx->dyn_str = ctx->bias + dynamic->d_un.d_ptr;
                if (ctx->dyn_str <= ctx->base) {
                    ctx->dyn_str = NULL;
                }
                break;
            }
            case DT_SYMTAB: {
                ctx->dyn_sym = (ElfW(Sym) *) (ctx->bias + dynamic->d_un.d_ptr);
                if (ctx->dyn_sym <= (ElfW(Sym) *) ctx->base) {
                    ctx->dyn_sym = NULL;
                }
                break;
            }
            case DT_PLTREL:
                ctx->is_use_rela = dynamic->d_un.d_val == DT_RELA;
                break;
            case DT_JMPREL: {
                ctx->rel_plt = (ElfW(Rel) *) (ctx->bias + dynamic->d_un.d_ptr);
                if (ctx->rel_plt <= (ElfW(Rel) *) ctx->base) {
                    ctx->rel_plt = NULL;
                }
                break;
            }
            case DT_PLTRELSZ:
                ctx->rel_plt_size = dynamic->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELA: {
                ctx->rel_dyn = (ElfW(Rel) *) (ctx->bias + dynamic->d_un.d_ptr);
                if (ctx->rel_dyn <= (ElfW(Rel) *) ctx->base) {
                    ctx->rel_dyn = NULL;
                }
                break;
            }
            case DT_RELSZ:
            case DT_RELASZ:
                ctx->rel_dyn_size = dynamic->d_un.d_val;
                break;
            case DT_ANDROID_REL:
            case DT_ANDROID_RELA: {
                ctx->rel_android = (ElfW(Rel) *) (ctx->bias + dynamic->d_un.d_ptr);
                if (ctx->rel_android <= (ElfW(Rel) *) ctx->base) {
                    ctx->rel_android = NULL;
                }
                break;
            }
            case DT_ANDROID_RELSZ:
            case DT_ANDROID_RELASZ:
                ctx->rel_android_size = dynamic->d_un.d_val;
                break;
            case DT_HASH: {
                ctx->elf_hash.exist = 1;
                ElfW(Word) *p = (ElfW(Word) *) (ctx->bias + dynamic->d_un.d_ptr);
                ctx->elf_hash.nbuckets = p[0];
                ctx->elf_hash.buckets = p + 2;
                ctx->elf_hash.hashval = ctx->elf_hash.buckets + ctx->elf_hash.nbuckets;
                break;
            }
            case DT_GNU_HASH: {
                ctx->gnu_hash.exist = 1;
                ElfW(Word) *p = (ElfW(Word) *) (ctx->bias + dynamic->d_un.d_ptr);
                ctx->gnu_hash.nbuckets = p[0];
                ctx->gnu_hash.symndx = p[1];
                ctx->gnu_hash.maskwords_bm = p[2];
                ctx->gnu_hash.shift2 = p[3];
                ctx->gnu_hash.bloom = (size_t *) (p + 4);
                ctx->gnu_hash.buckets =
                        (ElfW(Word) *) (ctx->gnu_hash.bloom + ctx->gnu_hash.maskwords_bm);
                ctx->gnu_hash.hashval =
                        ctx->gnu_hash.buckets + ctx->gnu_hash.nbuckets - ctx->gnu_hash.symndx;
                break;
            }
            default:
                break;
        }
    }
    if (0 != ctx->rel_android) {
        const char *rel = (const char *) ctx->rel_android;
        if (ctx->rel_android_size < 4 ||
            rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' || rel[3] != '2') {
            return;
        }
        ctx->rel_android += 4;
        ctx->rel_android_size -= 4;
    }
    ctx->valid = 1;
}

void Elf_UseFileContent(MemElfContext *ctx) {
    if (ctx == NULL || !ctx->valid) return;
    char *path = ctx->path;
    if (path[0] == 0) {
        updateProcessMaps(-1, 0);
        path = ctx->path;
    }
    if (path[0] == 0) return;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    off_t size = lseek(fd, 0, SEEK_END);
    if (size <= 0) return;
    ElfW(Ehdr) *elf = (ElfW(Ehdr) *) mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (elf == MAP_FAILED) return;
    char *shoff = ((char *) elf) + elf->e_shoff;
    for (int k = 0; k < elf->e_shnum; k++, shoff += elf->e_shentsize) {
        ElfW(Shdr) *sh = (ElfW(Shdr) *) shoff;
        switch (sh->sh_type) {
            case SHT_DYNSYM:
                if (ctx->FCdynsym) break;
                ctx->FCdynsym = realloc(ctx->FCdynsym, sh->sh_size);
                memcpy(ctx->FCdynsym, ((char *) elf) + sh->sh_offset, sh->sh_size);
                ctx->FCnsyms = (sh->sh_size / sizeof(ElfW(Sym)));
                break;
            case SHT_STRTAB:
                if (ctx->FCdynstr) break;
                ctx->FCdynstr = realloc(ctx->FCdynstr, sh->sh_size);
                memcpy(ctx->FCdynstr, ((char *) elf) + sh->sh_offset, sh->sh_size);
                break;
            case SHT_PROGBITS:
                if (!ctx->FCdynstr || !ctx->FCdynsym) break;
                ctx->FCbias = (off_t) sh->sh_addr - (off_t) sh->sh_offset;
                k = elf->e_shnum;
                break;
        }
    }
    munmap(elf, size);
    ctx->useFileContent = 1;
}

static inline uint32_t elf_hash(const char *name) {
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + *name++;
        if ((g = h & 0xf0000000)) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

static inline ElfW(Word) Elf_ElfHashSymOffset(MemElfContext *ctx, const char *name) {
    if (ctx == NULL || !ctx->valid || !ctx->elf_hash.exist || !ctx->elf_hash.buckets
        || !ctx->elf_hash.hashval || !ctx->dyn_sym || !ctx->dyn_str)
        return 0;
    uint32_t hash = elf_hash(name);
    const char *strings = ctx->dyn_str;
    for (ElfW(Word) idx = ctx->elf_hash.buckets[hash % ctx->elf_hash.nbuckets]; idx != 0;
         idx = ctx->elf_hash.hashval[idx]) {
        ElfW(Sym) *s = ctx->dyn_sym + idx;
        if (strcmp(strings + s->st_name, name) == 0) {
            return idx;
        }
    }
    return 0;
}

static inline uint32_t elf_gnu_hash(const char *s) {
    uint32_t h = 5381;
    unsigned char c;
    for (c = *s; c != '\0'; c = *++s) {
        h = h * 33 + c;
    }
    return h;
}

//static inline
ElfW(Word) Elf_GnuHashSymOffset(MemElfContext *ctx, const char *name) {
    if (ctx == NULL || !ctx->valid || !ctx->gnu_hash.exist || !ctx->gnu_hash.bloom
        || !ctx->gnu_hash.buckets || !ctx->gnu_hash.hashval || !ctx->dyn_sym || !ctx->dyn_str)
        return 0;
    size_t ELFCLASS_BITS = sizeof(ElfW(Addr)) * 8;
    uint32_t hash = elf_gnu_hash(name);
    size_t bloom_word = ctx->gnu_hash.bloom[(hash / ELFCLASS_BITS) % ctx->gnu_hash.maskwords_bm];
    uintptr_t mask = (uintptr_t) 1 << (hash % ELFCLASS_BITS) |
                     (uintptr_t) 1 << ((hash >> ctx->gnu_hash.shift2) % ELFCLASS_BITS);
    if ((mask & bloom_word) == mask) {
        ElfW(Word) idx = ctx->gnu_hash.buckets[hash % ctx->gnu_hash.nbuckets];
        if (idx >= ctx->gnu_hash.symndx) {
            const char *strings = ctx->dyn_str;
            do {
                ElfW(Sym) *sym = ctx->dyn_sym + idx;
                if (((ctx->gnu_hash.hashval[idx] ^ hash) >> 1) == 0 &&
                    strcmp(strings + sym->st_name, name) == 0) {
                    return idx;
                }
            } while ((ctx->gnu_hash.hashval[idx++] & 1) == 0);
        }
    }
    return 0;
}

static inline ElfW(Word) Elf_LinearSymOffset(MemElfContext *ctx, const char *name) {
    if (ctx == NULL || !ctx->valid || !ctx->gnu_hash.exist ||
        !ctx->dyn_sym || !ctx->dyn_str || !ctx->gnu_hash.symndx)
        return 0;
    const char *strings = ctx->dyn_str;
    for (ElfW(Word) idx = 0; idx < ctx->gnu_hash.symndx; idx++) {
        ElfW(Sym) *sym = ctx->dyn_sym + idx;
        if (strcmp(strings + sym->st_name, name) == 0) {
            return idx;
        }
    }
    return 0;
}

void *Elf_SymGet(MemElfContext *ctx, const char *name) {
    if (ctx == NULL || !ctx->valid) return NULL;
    if (ctx->useFileContent) {
        ElfW(Sym) *sym = ctx->FCdynsym;
        char *strings = (char *) ctx->FCdynstr;
        for (int k = 0; k < ctx->FCnsyms; k++, sym++)
            if (strcmp(strings + sym->st_name, name) == 0) {
                void *ret = (void *) ((char *) ctx->bias + sym->st_value);
                return ret;
            }
    }
    //内存方案
    ElfW(Word)
            idx = Elf_GnuHashSymOffset(ctx, name);
    if (!idx)
        idx = Elf_ElfHashSymOffset(ctx, name);
    if (!idx)
        idx = Elf_LinearSymOffset(ctx, name);
    if (idx) {
        ElfW(Sym) *sym = ctx->dyn_sym + idx;
        if (strcmp(ctx->dyn_str + sym->st_name, name) != 0) {
            return 0;
        }
        void *ret = (void *) ((char *) ctx->bias + sym->st_value);
        return ret;
    }
    return 0;
}

ElfW(Word) Elf_SymOffset(MemElfContext *ctx, const char *name) {
    if (ctx == NULL || !ctx->valid) return 0;
    ElfW(Word) idx = Elf_GnuHashSymOffset(ctx, name);
    if (!idx) idx = Elf_ElfHashSymOffset(ctx, name);
    if (!idx) idx = Elf_LinearSymOffset(ctx, name);
    return idx;
}

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    //.rel.dyn
#define ELF_R_GENERIC_ABS R_ARM_ABS32            //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_X86_64_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

static inline void
Elf_RelaModePLT(ElfW(Rela) *rela_base, ElfW(Addr) rela_size,
                MemElfContext *ctx, ElfW(Word) idx, ptrList *list) {
    if (!rela_base) return;
    const ElfW(Rela) *rela_end = rela_base + rela_size;
    const int is_plt = ctx->rela_plt == rela_base;
    for (const ElfW(Rela) *rela = rela_base; rela < rela_end; ++rela) {
        ElfW(Xword) r_info = rela->r_info;
        ElfW(Addr) r_offset = rela->r_offset;
        ElfW(Xword) r_sym = ELF_R_SYM(r_info);
        ElfW(Xword) r_type = ELF_R_TYPE(r_info);
        if (r_sym != idx) continue;
        if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
        if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) {
            continue;
        }
        char *addr = ctx->bias + r_offset;
        if (addr > ctx->base) {
            list->ptrs = realloc(list->ptrs, (list->size + 1) * sizeof(char *));
            list->ptrs[list->size++] = addr;
        }
        if (is_plt) break;
    }
}

static inline void
Elf_RelModePLT(ElfW(Rel) *rel_base, ElfW(Addr) rel_size,
               MemElfContext *ctx, ElfW(Word) idx, ptrList *list) {
    if (!rel_base) return;
    const ElfW(Rel) *rel_end = rel_base + rel_size;
    const int is_plt = ctx->rel_plt == rel_base;
    for (const ElfW(Rel) *rel = rel_base; rel < rel_end; ++rel) {
        ElfW(Xword) r_info = rel->r_info;
        ElfW(Addr) r_offset = rel->r_offset;
        ElfW(Xword) r_sym = ELF_R_SYM(r_info);
        ElfW(Xword) r_type = ELF_R_TYPE(r_info);
        if (r_sym != idx) continue;
        if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
        if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) {
            continue;
        }
        char *addr = ctx->bias + r_offset;
        if (addr > ctx->base) {
            list->ptrs = realloc(list->ptrs, (list->size + 1) * sizeof(char *));
            list->ptrs[list->size] = addr;
        }
        if (is_plt) break;
    }
}

void Elf_findPLT(MemElfContext *ctx, const char *name, ptrList *list) {
    if (ctx == NULL || !ctx->valid || name == NULL || list == NULL) return;
    ElfW(Word) idx = Elf_SymOffset(ctx, name);
    if (!idx) return;
    if (ctx->is_use_rela) {
        Elf_RelaModePLT(ctx->rela_plt, ctx->rela_plt_size, ctx, idx, list);
        Elf_RelaModePLT(ctx->rela_dyn, ctx->rela_dyn_size, ctx, idx, list);
        Elf_RelaModePLT(ctx->rela_android, ctx->rela_android_size, ctx, idx, list);
    } else {
        Elf_RelModePLT(ctx->rel_plt, ctx->rel_plt_size, ctx, idx, list);
        Elf_RelModePLT(ctx->rel_dyn, ctx->rel_dyn_size, ctx, idx, list);
        Elf_RelModePLT(ctx->rel_android, ctx->rel_android_size, ctx, idx, list);
    }
}


MapsList *processMaps = NULL;
MemElfContextList *memElfContextList = NULL;

MemElfContext *findMemElfContext(char *base, int withOpen, int withAppend) {
    MemElfContext *ctx = NULL;
    if (base == NULL) return ctx;
    pthread_mutex_lock(&memElfContextList_Mutex);
    if (memElfContextList == NULL) {
        memElfContextList = malloc(sizeof(MemElfContextList));
        memset(memElfContextList, 0, sizeof(MemElfContextList));
    }
    for (int i = 0; i < memElfContextList->size; i++) {
        if (memElfContextList->ctxs[i].base == base) {
            ctx = &memElfContextList->ctxs[i];
            if (withOpen) Elf_Open(ctx);
            pthread_mutex_unlock(&memElfContextList_Mutex);
            return ctx;
        }
    }
    if (!withAppend) {
        pthread_mutex_unlock(&memElfContextList_Mutex);
        return ctx;
    }
    memElfContextList->ctxs =
            realloc(memElfContextList->ctxs, (memElfContextList->size + 1) * sizeof(MemElfContext));
    ctx = &memElfContextList->ctxs[memElfContextList->size];
    memset(ctx, 0, sizeof(MemElfContext));
    ctx->base = base;
    pthread_mutex_init(&ctx->mutex, NULL);
    if (withOpen) Elf_Open(ctx);
    memElfContextList->size++;
    pthread_mutex_unlock(&memElfContextList_Mutex);
    return ctx;
}

void updateProcessMaps(pid_t pid, int withPrepareContext) {
    pthread_mutex_lock(&processMaps_Mutex);
    if (processMaps == NULL) {
        processMaps = malloc(sizeof(MapsList));
        memset(processMaps, 0, sizeof(MapsList));
    } else {
        free(processMaps->maps);
        memset(processMaps, 0, sizeof(MapsList));
    }
    FILE *f_maps = NULL;
    if (pid < 0) {
        f_maps = fopen("/proc/self/maps", "r");
    } else {
        char maps_path[PATH_MAX] = {0};
        sprintf(maps_path, "/proc/%d/maps", pid);
        f_maps = fopen(maps_path, "r");
    }
    if (f_maps == NULL) {
        pthread_mutex_unlock(&processMaps_Mutex);
        return;
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, f_maps)) != -1) {
        line[read - 1] = '\0';
        processMaps->maps = realloc(processMaps->maps,
                                    (processMaps->size + 1) * sizeof(MapsStruct));
        MapsStruct *maps = &processMaps->maps[processMaps->size];
        memset(maps, 0, sizeof(MapsStruct));
        char permission[5] = {0};
        sscanf(line, "%p-%p %c%c%c%c %lx %x:%x %ld %s", &maps->start, &maps->end,
               &permission[0], &permission[1], &permission[2], &permission[3],
               &maps->offset, &maps->devicemajor, &maps->deviceminor, &maps->inode, maps->path);
        maps->permission = PROT_NONE;
        //rwxp
        if (permission[0] == 'r') maps->permission |= PROT_READ;
        if (permission[1] == 'w') maps->permission |= PROT_WRITE;
        if (permission[2] == 'x') maps->permission |= PROT_EXEC;
        if (permission[3] == 's') maps->shared = 1;
        else if (permission[3] == 'p') maps->shared = 0;
        else maps->shared = -1;
        processMaps->size++;
        if (withPrepareContext) {
            if ((maps->shared==0) && (maps->permission & PROT_READ)
                && (maps->path[0] != 0) && (maps->path[0] != '[')) {
                char elfbuff[5]={0};
                memcpy(elfbuff, maps->start, 4);
                if (memcmp(elfbuff, ELFMAG, SELFMAG) == 0) {
                    MemElfContext *ctx = findMemElfContext(maps->start, 0, 1);
                    if (ctx) {
                        strcpy(ctx->path, maps->path);
                    }
                }
            }
        } else {
            if ((maps->shared==0) && (maps->permission & PROT_READ)
                && (maps->path[0] != 0) && (maps->path[0] != '[')) {
                MemElfContext *ctx = findMemElfContext(maps->start, 0, 0);
                if (ctx && ctx->path[0] == 0) {
                    strcpy(ctx->path, maps->path);
                }
            }
        }
    }
    pthread_mutex_unlock(&processMaps_Mutex);
    if (line) free(line);
    fclose(f_maps);
}

MemElfContext *getModuleBase(pid_t pid, const char *module_name) {
    int cacheSuccess = 0;
    retry:;
    //先从缓存中查找
    if (processMaps != NULL) {
        for (int i = 0; i < processMaps->size; i++) {
            if (strstr(processMaps->maps[i].path, module_name)) {
                return findMemElfContext(processMaps->maps[i].start, 1, 1);
            }
        }
    }
    if (cacheSuccess) return NULL;
    cacheSuccess = 1;
    //缓存中没有再重新获取
    updateProcessMaps(pid, 1);
    goto retry;
}

MapsStruct *getModuleMaps(pid_t pid, char *base) {
    int cacheSuccess = 0;
    retry:;
    //先从缓存中查找
    if (processMaps != NULL) {
        for (int i = 0; i < processMaps->size; i++) {
            if (processMaps->maps[i].start == base) {
                return &processMaps->maps[i];
            }
        }
    }
    if (cacheSuccess) return NULL;
    cacheSuccess = 1;
    //缓存中没有再重新获取
    updateProcessMaps(pid, 0);
    goto retry;
}