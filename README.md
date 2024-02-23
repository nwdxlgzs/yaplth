# YAPLTH
> Yet Another Procedure Linkage Table Hook

## 提供的Hook方案
> Plt-Got Hook

## 使用方法
- Hook：通过`yaplth_addHook`添加，然后调用`yaplth_commitHook`执行。
```c
...
#include "yaplth.h"
typedef int (*foo_t)(int a,int b);
static foo_t real_foo = NULL;
static int yaplth_foo(int a,int b) {
    return real_foo(a, b);
}
int main(const int argc,const char** argv) {
    Dl_info info;
    if (dladdr(foo, &info)) {
        yaplth_addHook(info.dli_fbase, "foo", (void *) yaplth_foo,
                       (void **) &real_foo);
        yaplth_commitHook(NULL);
    }
    return 0;
}
...
```
- UnHook：通过`yaplth_removeHook`填入`yaplth_addHook`加入的原Hook函数即可。

```c
...
#include "yaplth.h"
static int yaplth_foo(int a,int b) {
    return 0;
}
int main(const int argc,const char** argv) {
    yaplth_removeHook((void *) yaplth_foo);
    return 0;
}
...
```
- 过滤器：`yaplth_commitHook`接受过滤器，返回非0则执行。
```c
typedef int (*yaplth_filter_t)(MapsStruct *workMap, MemElfContext *workElf,
                               uintptr_t *where, uintptr_t raw_value, uintptr_t new_value);
```

## 额外说明
      我没有做太多测试，不确定好不好用。
      我考虑过做互斥锁，也加了，但是懒得梳理流程了，加的不是很正确，欢迎修改更正。
      我考虑过多次Hook同一个函数，但是没完全解决，所以请当成只能Hook一次的工具吧（移除后可以重新Hook这个是没问题的）
      为了解决安卓N限制，我同样在写完elftool后实现了我自己的dlfcn_compat，提供属于我的解决方案，这里不过多介绍，请自行查看源码。

## license开源许可
     这个项目如果源码进行了修改需要公开，并且修改的项目（本项目部分）也需要遵从本协议。
     如果没有对源码有任何修改，其他情况遵循MIT协议。
     以上是本开源许可，大致上是一个MPL协议，但又不是MPL。