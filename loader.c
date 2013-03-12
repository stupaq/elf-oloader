// MAKE SHARED LIBRARY
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>

#include "loader.h"

////// ERR

#define CATCH catch__
#define THROW(code) {fprintf(stderr, #code"; on line %d;\n", __LINE__); goto CATCH;}
#define TRY_SYS(code) if ((code) < 0) THROW(code)
#define TRY_PTR(code) if (!(code)) THROW(code)
#define TRY_TRUE(code) if (!(code)) THROW(code)
#define TRY_ZERO(code) if ((code) != 0) THROW(code)

//////

struct section {
  uintptr_t mmap_start;
  /* memory chunk is mmapped iff length >0 */
  size_t mmap_length;
  int mmap_prot;
  uintptr_t addr;
};

struct module {
  size_t sections_sz;
  struct section *sections;
};

uint32_t addr_align(uint32_t addr, uint32_t align) {
  assert((align & (align - 1)) == 0);
  return (align > 0) ? (addr + align - 1) & (~(align - 1)) : addr;
}

int alloc_section(struct section *section, const Elf32_Shdr *elf_shdr) {
  assert(section->mmap_length == 0);

  if (elf_shdr->sh_addr == 0) {
    size_t align = (elf_shdr->sh_addralign > 1) ? elf_shdr->sh_addralign : 0;
    section->mmap_length = elf_shdr->sh_size + align; // OPTIMIZE

    TRY_TRUE((section->mmap_start = (uintptr_t) mmap(
            NULL,
            section->mmap_length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0)) != (uintptr_t) MAP_FAILED);

    section->addr = addr_align(section->mmap_start, align);
    /*
       fprintf(stderr, "alloc %u %u %u %u\n",
       section->addr,
       section->mmap_start,
       section->mmap_length,
       elf_shdr->sh_addralign);
       */
  } else {
    // TODO
    assert(0);
  }

  section->mmap_prot = PROT_READ;
  if (elf_shdr->sh_flags & SHF_EXECINSTR)
    section->mmap_prot |= PROT_EXEC;
  if (elf_shdr->sh_flags & SHF_WRITE)
    section->mmap_prot |= PROT_WRITE;
  return 0;

CATCH:
  section->mmap_length = 0;
  return -1;
}

int dealloc_section(struct section *section) {
  if (section->mmap_length == 0)
    return 0;
  TRY_SYS(munmap((void *) section->mmap_start, section->mmap_length));
  return 0;
CATCH:
  return -1;
}

struct module *module_load(const char *filename, getsym_t getsym_fun,
    void *getsym_arg) {
  FILE* elf_file = NULL;
  Elf32_Shdr *section_headers = NULL;
  struct module *mod = NULL;

  TRY_PTR(mod = malloc(sizeof(struct module)));
  memset(mod, 0, sizeof(struct module));

  TRY_PTR(elf_file = fopen(filename, "rb"));

  Elf32_Ehdr elf_header;
  TRY_TRUE(fread(&elf_header, sizeof(elf_header), 1, elf_file) == 1);

  TRY_TRUE(elf_header.e_ident[EI_MAG0] == ELFMAG0
      && elf_header.e_ident[EI_MAG1] == ELFMAG1
      && elf_header.e_ident[EI_MAG2] == ELFMAG2
      && elf_header.e_ident[EI_MAG3] == ELFMAG3);
  TRY_TRUE(elf_header.e_ident[EI_CLASS] == ELFCLASS32);
  TRY_TRUE(elf_header.e_ident[EI_DATA] == ELFDATA2LSB);
  TRY_TRUE(elf_header.e_type == ET_REL);
  TRY_TRUE(elf_header.e_machine == EM_386);

  TRY_PTR(elf_header.e_shoff);
  TRY_ZERO(fseek(elf_file, elf_header.e_shoff, SEEK_SET));
  TRY_TRUE(elf_header.e_shentsize == sizeof(Elf32_Shdr));

  // If the number of sections is greater than or equal to SHN_LORESERVE
  // (0xff00), e_shnum has the value SHN_UNDEF (0) and the actual number of
  // section header table entries is contained in the sh_size field of the
  // section header at index 0
  if (elf_header.e_shnum == SHN_UNDEF) {
    Elf32_Shdr section_header;
    TRY_TRUE(fread(&section_header, elf_header.e_shentsize, 1, elf_file) == 1);
    elf_header.e_shnum = section_header.sh_size;
    TRY_ZERO(fseek(elf_file, elf_header.e_shoff, SEEK_SET));
  }

  TRY_PTR(section_headers = malloc(sizeof(Elf32_Shdr) * elf_header.e_shnum));
  TRY_TRUE(fread(section_headers, elf_header.e_shentsize, elf_header.e_shnum,
        elf_file) == elf_header.e_shnum);
  // Count and allocate needed mmap blocks
  mod->sections_sz = elf_header.e_shnum;
  TRY_PTR(mod->sections = malloc(sizeof(struct section) * mod->sections_sz));
  memset(mod->sections, 0, sizeof(struct section) * mod->sections_sz);
  // Load sections
  for (size_t idx = 0; idx < elf_header.e_shnum; idx++) {
    Elf32_Shdr *shdr = section_headers + idx;
    if (!(shdr->sh_flags & SHF_ALLOC) || shdr->sh_size == 0)
      continue;
    struct section *section = mod->sections + idx;
    switch (shdr->sh_type) {
      case SHT_NULL:
        break;
      case SHT_SYMTAB:
        // TODO
        break;
      case SHT_STRTAB:
        // TODO
        break;
      case SHT_REL:
        // TODO
        break;
      case SHT_NOBITS:
        TRY_SYS(alloc_section(section, shdr));
        memset((void *) shdr->sh_addr, 0, shdr->sh_size);
        break;
      case SHT_PROGBITS:
      default:
        TRY_SYS(alloc_section(section, shdr));
        TRY_ZERO(fseek(elf_file, shdr->sh_offset, SEEK_SET));
        TRY_TRUE(fread((void *) section->addr, shdr->sh_size, 1, elf_file) == 1);
        // TODO
        break;
    }
  }

  // Set-up sections protection
  for (size_t idx = 0; idx < elf_header.e_shnum; idx++) {
  }

  free(section_headers);
  fclose(elf_file);

  fprintf(stderr, "module_load succeeded\n");
  return mod;

CATCH:
  fprintf(stderr, "module_load failed, errno %d: %s\n", errno, strerror(errno));

  free(section_headers);
  fclose(elf_file);
  module_unload(mod);
  return NULL;
}

void *module_getsym(struct module *mod, const char *name) {
  ((void) mod);
  ((void) name);
  // TODO
  return 0;
}

void module_unload(struct module *mod) {
  if (NULL == mod)
    return;

  // TODO
  for (size_t idx = 0; idx < mod->sections_sz; idx++) {
    dealloc_section(mod->sections + idx);
  }
  free(mod->sections);
  free(mod);
}
