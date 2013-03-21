#include "loader.h"
#include <stdio.h>

void *getsym_none(void *arg, const char *name) {
	return 0;
}

int main() {
	struct module *mod;
	mod = module_load("abs.o", getsym_none, 0);
	int res = 0;
	if (!mod) {
		printf("ERROR: Can't load module.o\n");
		return 1;
	}
	char **var = module_getsym(mod, "nazwa");
	if (!var) {
		printf("ERROR: Can't find symbol\n");
		return 1;
	}
	printf("%s\n", *var);
	module_unload(mod);
	return 0;
}
