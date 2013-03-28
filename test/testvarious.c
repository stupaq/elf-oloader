#include "loader.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

int zonk = 0x666;

void *getundef(void *arg, const char * name)
{
  if(!strcmp(name, "pulp"))
  {
    return &zonk;
  }

  return 0;
}

struct int_st
{
  int a;
  int b;
  int c;
};

int testVar(struct module* mod, const char *name, int val)
{
  void *var = module_getsym(mod, name);

  if(!var)
  {
    printf("ERROR: Can't find %s\n", name);
  }

  return *((int *)var) == val;
}

int testVarLL(struct module* mod, const char *name, long long int val)
{
  void *var = module_getsym(mod, name);

  if(!var)
  {
    printf("ERROR: Can't find %s\n", name);
  }

  return *((long long int *)var) == val;
}

int testFun(struct module* mod, const char *name, int val)
{
  int (*ifunv)() = module_getsym(mod, name);

  if(!ifunv)
  {
    printf("ERROR: Can't find %s\n", name);
  }

  return ifunv() == val;
}

int testStr(struct module *mod, const char* name, const char* val)
{
  const char **var = module_getsym(mod, name);
  if(!var)
  {
    printf("ERROR: Can't find %s\n", name);
  }

  return !strcmp(*var, val);
}

int testPtr(struct module *mod, const char *name, double *val)
{
  double **ptr = module_getsym(mod, name);

  if(!ptr)
  {
    printf("ERROR: Can't find %s\n", name);
  }

  return *ptr == val;
}

void test(struct module* mod)
{
  assert(testVar(mod, "dingding", 5));
  assert(testVar(mod, "omg", 0x69));
  assert(testVar(mod, "global_zero", 0));
  assert(testVar(mod, "global_zero2", 0));

  struct int_st *st = module_getsym(mod, "st");
  assert(st->a == 1);
  assert(st->b == 2);
  assert(st->c == 3);

  assert(testFun(mod, "ret4", 0x42));
  assert(testFun(mod, "ret8", 8));
  assert(testFun(mod, "sum", 8 + 0x42));
  assert(testFun(mod, "wrap", zonk));
  assert(testFun(mod, "wrap2", zonk + 1));

  assert(testStr(mod, "sup", "what's up"));
  assert(testStr(mod, "how", "how are you today?"));

  assert(testVarLL(mod, "lucky", 7));
  assert(testVarLL(mod, "big", 123456789123456789LL));

  assert(testPtr(mod, "nullptr", (double *)0));
  assert(testPtr(mod, "oneptr", (double *)1));
  assert(testPtr(mod, "fortytwoptr", (double *)42));
}

int main() {
	struct module *mod;

	mod = module_load("various.o", getundef, 0);
	if (!mod) {
		printf("ERROR: Can't load various.o\n");
		return 1;
	}

  test(mod);

	module_unload(mod);

	mod = module_load("various.o", getundef, 0);
	if (!mod) {
		printf("ERROR: Can't load various.o\n");
		return 1;
	}

  test(mod);

	module_unload(mod);

  printf("OK\n");

	return 0;
}
