extern int pulp;

int global_zero = 0;

int dingding = 5;
int omg = 0x69;

int global_zero2 = 0;

const char *sup= "what's up";
const char *how= "how are you today?";

long long int lucky = 7;
long long int big = 123456789123456789LL;

double *nullptr = 0;
double *oneptr = (double *)1;
double *fortytwoptr = (double *)42;

struct int_st
{
  int a;
  int b;
  int c;
} st = {.a = 1, .b = 2, .c = 3};

int ret4()
{
  return 0x42;
}

int ret8()
{
  return 8;
}

int sum()
{
  return ret8() + ret4();
}


int wrap()
{
  return pulp;
}

int wrap2()
{
  return pulp + 1;
}
