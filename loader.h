#ifndef LOADER_H
#define LOADER_H

#ifdef __cplusplus
extern "C" {
#endif

struct module;

typedef void *(*getsym_t) (void *arg, const char *name);

struct module *module_load(
		const char *filename,
		getsym_t getsym_fun,
		void *getsym_arg);

void *module_getsym(struct module *mod, const char *name);

void module_unload(struct module *mod);

#ifdef __cplusplus
}
#endif

#endif
