#ifndef ELFTOOL_H
#define ELFTOOL_H

#include "android/log.h"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "yaplth", __VA_ARGS__)
#include <link.h>
#include <limits.h>
#include <pthread.h>
#include <dlfcn.h>

//// 暂时目前的方案不用dl_iterate_phdr，手动的。
//extern __attribute((weak)) int
//dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

typedef struct ptrList {
    void **ptrs;
    size_t size;
} ptrList;
typedef struct PtrBakup {
    void *where;//哪里的指针
    void *raw_value;//原始值
    void *new_value;//新值
    int worked;//是否已经hook
    struct PtrBakup *next;
} PtrBakup;
typedef struct MemElfContext {
    char *base; // 指向ELF文件在内存中的基地址
    char path[PATH_MAX]; // ELF文件的路径
    int opened; // 标志位，扫描会自动创建MemElfContext，但是不执行Elf_Open
    char *bias; // 指向ELF文件在内存中的偏移地址
    int valid; // 标志位，指示结构体是否包含有效的ELF上下文信息
    ElfW(Ehdr) *header; // 指向ELF头部的指针
    ElfW(Phdr) *phdr; // 指向程序头表的指针
    ElfW(Dyn) *dynamic; // 指向动态段的指针
    int dynamic_size; // 动态段的大小
    struct { // ELF哈希表，用于快速符号查找
        int exist; // 标志位，指示哈希表是否存在
        ElfW(Word) nbuckets; // 哈希桶的数量
        ElfW(Word) *buckets; // 指向哈希桶数组的指针
        ElfW(Word) *hashval; // 指向哈希值数组的指针
    } elf_hash;
    struct { // GNU哈希表，是另一种用于符号查找的哈希表
        int exist; // 标志位，指示GNU哈希表是否存在
        ElfW(Word) nbuckets; // 哈希桶的数量
        ElfW(Word) symndx; // 符号表索引
        ElfW(Word) maskwords_bm; // Bloom过滤器掩码词数
        ElfW(Word) shift2; // Bloom过滤器的位移量
        size_t *bloom; // 指向Bloom过滤器数组的指针
        ElfW(Word) *buckets; // 指向哈希桶数组的指针
        ElfW(Word) *hashval; // 指向链表数组的指针
    } gnu_hash;
    char *dyn_str; // 指向动态字符串表的指针
    ElfW(Sym) *dyn_sym; // 指向动态符号表的指针
    int is_use_rela; // 标志位，指示是否使用 RELA 重定位条目
    union { // 指向特定于Android的重定位条目的指针（如果存在）
        ElfW(Rel) *rel_android;
        ElfW(Rela) *rela_android;
    };
    union { // Android特定重定位条目的大小
        ElfW(Xword) rel_android_size;
        ElfW(Xword) rela_android_size;
    };
    union { // 指向动态重定位条目的指针
        ElfW(Rel) *rel_dyn;
        ElfW(Rela) *rela_dyn;
    };
    union { // 动态重定位条目的大小
        ElfW(Xword) rel_dyn_size;
        ElfW(Xword) rela_dyn_size;
    };
    union { // 指向程序链接表（PLT）重定位条目的指针
        ElfW(Rel) *rel_plt;
        ElfW(Rela) *rela_plt;
    };
    union { // PLT重定位条目的大小
        ElfW(Xword) rel_plt_size;
        ElfW(Xword) rela_plt_size;
    };
    int bydlopen; // 标志位，指示是否是通过 dlopen 加载的（得dlclose）
    int useFileContent; // 标志位，指示是否使用了来自文件的内容
    char *FCdynstr;//文件内容中的动态字符串表
    ElfW(Sym) *FCdynsym;//文件内容中的动态符号表
    int FCnsyms;//文件内容中的符号数量
    off_t FCbias;//文件内容中的偏移地址
    pthread_mutex_t mutex;// Hook时用的锁
    PtrBakup *hooks;//Hook操作记录（暂时未处理重复Hook同一函数的情况）
} MemElfContext;

extern void Elf_Open(MemElfContext *ctx);

extern void *Elf_SymGet(MemElfContext *ctx, const char *name);

extern ElfW(Word) Elf_SymOffset(MemElfContext *ctx, const char *name);

extern void Elf_UseFileContent(MemElfContext *ctx);

extern void Elf_findPLT(MemElfContext *ctx, const char *name, ptrList *list);

typedef struct MapsStruct {
    char *start;
    char *end;
    int permission;
    int shared;
    size_t offset;
    unsigned int devicemajor;
    unsigned int deviceminor;
    ino_t inode;
    char path[PATH_MAX];
} MapsStruct;
typedef struct MapsList {
    MapsStruct *maps;
    size_t size;
} MapsList;
typedef struct MemElfContextList {
    MemElfContext *ctxs;
    size_t size;
} MemElfContextList;
extern MapsList *processMaps;
extern pthread_mutex_t processMaps_Mutex;
extern MemElfContextList *memElfContextList;
extern pthread_mutex_t memElfContextList_Mutex;

extern MemElfContext *findMemElfContext(char *base, int withOpen, int withAppend);

extern void updateProcessMaps(pid_t pid, int withPrepareContext);

extern MemElfContext *getModuleBase(pid_t pid, const char *module_name);

extern MapsStruct *getModuleMaps(pid_t pid, char *base);

#endif //ELFTOOL_H
