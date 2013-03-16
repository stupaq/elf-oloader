#include "loader.h"
#include <stdio.h>

int main() {
	struct module *mod;
	mod = module_load("missing_module_name.o", 0, 0);
	if (mod) {
		printf("ERROR: Loaded non-existing module.\n");
		return 1;
	}
	module_unload(mod);
  printf("OK\n");
	return 0;
}
