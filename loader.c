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

//#define DEBUG

#define CATCH catch__
#ifdef DEBUG
#define THROW(code) {fprintf(stderr, #code"; on line %d;\n", __LINE__); goto CATCH;}
#else
#define THROW(code) {goto CATCH;}
#endif
#define TRY_SYS(code) if ((code) < 0) THROW(code)
#define TRY_PTR(code) if (!(code)) THROW(code)
#define TRY_TRUE(code) if (!(code)) THROW(code)

struct section {
  uintptr_t mmap_start;
  /* memory chunk is mmapped iff length >0 */
  size_t mmap_length;
  int mmap_prot;
  uintptr_t addr;
  size_t size;
};

typedef Elf32_Sym symbol_t;

struct module {
  size_t sections_sz;
  struct section *sections;
  size_t strings_sz;
  char *strings;
  size_t symbols_sz;
  symbol_t *symbols;
};

uint32_t addr_align(uint32_t addr, uint32_t align) {
  assert((align & (align - 1)) == 0);
  return (align > 0) ? (addr + align - 1) & (~(align - 1)) : addr;
}

int is_allocated(struct section *section) {
  return section->mmap_length > 0;
}

int alloc_section(struct section *section, const Elf32_Shdr *elf_shdr) {
  assert(!is_allocated(section));

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
    section->size = elf_shdr->sh_size;
  } else {
    // TODO
    assert(0);
  }

  section->mmap_prot = PROT_READ;
  if (elf_shdr->sh_flags & SHF_EXECINSTR)
    section->mmap_prot |= PROT_EXEC;
  if (elf_shdr->sh_flags & SHF_WRITE)
    section->mmap_prot |= PROT_WRITE;

  assert(is_allocated(section));
  return 0;
CATCH:
  section->mmap_length = 0;
  return -1;
}

int dealloc_section(struct section *section) {
  if (is_allocated(section)) {
    TRY_SYS(munmap((void *) section->mmap_start, section->mmap_length));
    return 0;
  }
CATCH:
  return -1;
}

int read_symbol_table(struct module *mod, Elf32_Shdr *elf_shdr, FILE* elf_file) {
  TRY_TRUE(elf_shdr->sh_type == SHT_SYMTAB);
  TRY_TRUE(sizeof(Elf32_Sym) == elf_shdr->sh_entsize);
  size_t rem = elf_shdr->sh_size % elf_shdr->sh_entsize;
  TRY_TRUE(rem == 0);
  // Assuming there is only one symbols table
  TRY_TRUE(fseek(elf_file, elf_shdr->sh_offset, SEEK_SET) == 0);
  mod->symbols_sz = elf_shdr->sh_size / elf_shdr->sh_entsize;
  // We read symbols as Elf32_Sym but we store them internally as symbol_t
  // Elf32_Sym is known only to loading code
  TRY_TRUE(sizeof(Elf32_Sym) == sizeof(symbol_t));
  TRY_PTR(mod->symbols = malloc(mod->symbols_sz * sizeof(symbol_t)));
  TRY_TRUE(fread(mod->symbols, sizeof(symbol_t), mod->symbols_sz,
        elf_file) == mod->symbols_sz);
  return 0;
CATCH:
  free(mod->symbols);
  mod->symbols = NULL;
  return -1;
}

int read_string_table(struct module *mod, Elf32_Shdr *elf_shdr, FILE* elf_file) {
  TRY_TRUE(elf_shdr->sh_type == SHT_STRTAB);
  TRY_TRUE(elf_shdr->sh_size > 0);
  // Assuming there is only one symbols table (which implies only one
  // associated strings table)
  mod->strings_sz = elf_shdr->sh_size;
  TRY_PTR(mod->strings = malloc(mod->strings_sz));
  TRY_TRUE(fseek(elf_file, elf_shdr->sh_offset, SEEK_SET) == 0);
  TRY_TRUE(fread(mod->strings, mod->strings_sz, 1, elf_file) == 1);
  TRY_TRUE(mod->strings[0] == '\0');
  TRY_TRUE(mod->strings[mod->strings_sz - 1] == '\0');
  return 0;
CATCH:
  free(mod->strings);
  mod->strings = NULL;
  return -1;
}

#define ST_NOTYPE (1 << STT_NOTYPE)
#define ST_OBJECT (1 << STT_OBJECT)
#define ST_FUNC (1 << STT_FUNC)
#define ST_SECTION (1 << STT_SECTION)
#define ST_ANY_ALLOWED (ST_NOTYPE | ST_OBJECT | ST_FUNC | ST_SECTION)

#define SYM_ST_INFO(info) \
  ((uint32_t) (1 << ELF32_ST_TYPE(symbol->st_info)))
#define IS_RES_SHNDX(shndx) \
  (SHN_LORESERVE <= (shndx))
#define IS_VALID_SHNDX(shndx) \
  ((shndx) != SHN_UNDEF && !IS_RES_SHNDX(shndx))

struct section *get_section(struct module *mod, size_t shndx) {
  TRY_TRUE(shndx < mod->sections_sz);
  return mod->sections + shndx;
CATCH:
  return NULL;
}

char *get_string(struct module *mod, const size_t name) {
  TRY_TRUE(name < mod->strings_sz);
  return mod->strings + name;
CATCH:
  return NULL;
}

uintptr_t get_symbol_addr(struct module *mod, const symbol_t *symbol, const uint32_t type) {
  // We skip symbols from special sections and those of not matching type
  if (IS_VALID_SHNDX(symbol->st_shndx) && (SYM_ST_INFO(symbol->st_info) & type)) {
    struct section *section;
    TRY_PTR(section = get_section(mod, symbol->st_shndx));
    return section->addr + symbol->st_value;
  }
CATCH:
  return 0;
}

uintptr_t find_symbol(struct module *mod, const char *name, const uint32_t type) {
  for (size_t idx = 0; idx < mod->symbols_sz; idx++) {
    symbol_t *symbol = mod->symbols + idx;
    char *sym_name = get_string(mod, symbol->st_name);
    if (strcmp(name, sym_name) == 0) {
      return get_symbol_addr(mod, symbol, type);
    }
  }
  return 0;
}

int do_relocation(struct module *mod, struct section *dest_section,
    const Elf32_Rel *relocation, getsym_t getsym_fun, void *getsym_arg ) {
  size_t symbol_idx = ELF32_R_SYM(relocation->r_info);
  symbol_t *symbol = mod->symbols + symbol_idx;
  TRY_TRUE(!IS_RES_SHNDX(symbol->st_shndx));
#ifdef DEBUG
  fprintf(stderr, "%u -> %s shndx: %u type: %u\n",
      symbol_idx,
      get_string(mod, symbol->st_name),
      symbol->st_shndx,
      ELF32_ST_TYPE(symbol->st_info));
#endif
  if ((SYM_ST_INFO(symbol->st_info) & ST_ANY_ALLOWED)) {
    uint32_t symbol_addr = 0;
    if (symbol->st_shndx == SHN_UNDEF) {
      symbol_addr = (uint32_t) getsym_fun(getsym_arg, get_string(mod, symbol->st_name));
    } else {
      struct section *section;
      TRY_PTR(section = get_section(mod, symbol->st_shndx));
      TRY_TRUE(is_allocated(section));
      TRY_TRUE(symbol->st_value < section->size);
      symbol_addr = (uint32_t) (section->addr + symbol->st_value);
    }

    uint32_t *destination = (uint32_t *) (dest_section->addr + relocation->r_offset);
    switch (ELF32_R_TYPE(relocation->r_info)) {
      case R_386_32:
        *destination = *destination + symbol_addr;
        break;
      case R_386_PC32:
        *destination = *destination + symbol_addr - (uint32_t) destination;
        break;
      default:
        // Unrecognized relocation type encountered
        TRY_TRUE(0);
    }
  }
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
  TRY_TRUE(fseek(elf_file, elf_header.e_shoff, SEEK_SET) == 0);
  TRY_TRUE(elf_header.e_shentsize == sizeof(Elf32_Shdr));

  // If the number of sections is greater than or equal to SHN_LORESERVE
  // (0xff00), e_shnum has the value SHN_UNDEF (0) and the actual number of
  // section header table entries is contained in the sh_size field of the
  // section header at index 0
  // We do not handle this extension
  TRY_TRUE(elf_header.e_shnum != SHN_UNDEF);
  TRY_TRUE(elf_header.e_shnum < SHN_LORESERVE);

  TRY_PTR(section_headers = malloc(sizeof(Elf32_Shdr) * elf_header.e_shnum));
  TRY_TRUE(fread(section_headers, elf_header.e_shentsize, elf_header.e_shnum,
        elf_file) == elf_header.e_shnum);
  // Count and create sections
  mod->sections_sz = elf_header.e_shnum;
  TRY_PTR(mod->sections = malloc(sizeof(struct section) * mod->sections_sz));
  memset(mod->sections, 0, sizeof(struct section) * mod->sections_sz);
  // Not actually first global but we will treat all of them as global
  size_t global_sym_idx = 0;
  size_t symtab_idx = 0;
  // Load sections
  for (size_t idx = 0; idx < elf_header.e_shnum; idx++) {
    Elf32_Shdr *shdr = section_headers + idx;
    struct section *section;
    TRY_PTR(section = get_section(mod, idx));
    switch (shdr->sh_type) {
      case SHT_NULL:
      case SHT_STRTAB:
        // We will read appropriate strings table with symbols table
      case SHT_REL:
        // We will perform relocations later on
        break;
      case SHT_SYMTAB:
        TRY_TRUE(symtab_idx == 0);
        symtab_idx = idx;
        TRY_SYS(read_symbol_table(mod, shdr, elf_file));
        global_sym_idx = shdr->sh_info;
        // Field sh_link contains section header index of associated string table
        TRY_TRUE(IS_VALID_SHNDX(shdr->sh_link) && shdr->sh_link < elf_header.e_shnum);
        TRY_SYS(read_string_table(mod, section_headers + shdr->sh_link, elf_file));
        break;
      case SHT_NOBITS:
        if ((shdr->sh_flags & SHF_ALLOC) && shdr->sh_size > 0) {
          TRY_SYS(alloc_section(section, shdr));
          memset((void *) shdr->sh_addr, 0, shdr->sh_size);
        }
        break;
      case SHT_PROGBITS:
      default:
        if ((shdr->sh_flags & SHF_ALLOC) && shdr->sh_size > 0) {
          TRY_SYS(alloc_section(section, shdr));
          TRY_TRUE(fseek(elf_file, shdr->sh_offset, SEEK_SET) == 0);
          TRY_TRUE(fread((void *) section->addr, shdr->sh_size, 1, elf_file) == 1);
        }
        break;
    }
  }
  TRY_PTR(mod->strings);
  TRY_PTR(mod->symbols);

  // Perform relocations
  for (size_t idx = 0; idx < elf_header.e_shnum; idx++) {
    Elf32_Shdr *shdr = section_headers + idx;
    if (shdr->sh_type == SHT_REL && shdr->sh_link == symtab_idx) {
      // TODO mising (shdr->sh_flags & SHF_INFO_LINK)
      TRY_TRUE(fseek(elf_file, shdr->sh_offset, SEEK_SET) == 0);
      TRY_TRUE(sizeof(Elf32_Rel) == shdr->sh_entsize);
      size_t rel_num = shdr->sh_size / shdr->sh_entsize;
      TRY_TRUE(shdr->sh_size == rel_num * shdr->sh_entsize);

      struct section *dest_section;
      TRY_PTR(dest_section = get_section(mod, shdr->sh_info));
      for (size_t idx = 0; idx < rel_num; idx++) {
        Elf32_Rel relocation;
        TRY_TRUE(fread(&relocation, sizeof(Elf32_Rel), 1, elf_file) == 1);
        TRY_SYS(do_relocation(mod, dest_section, &relocation, getsym_fun,
              getsym_arg));
      }
    }
  }

  // Compress symbol table (remove local symbols after relocations)
  TRY_TRUE(global_sym_idx < mod->symbols_sz);
  mod->symbols_sz -= global_sym_idx;
  memmove(mod->symbols, mod->symbols + global_sym_idx,
      mod->symbols_sz * sizeof(symbol_t));
  TRY_PTR(mod->symbols = realloc(mod->symbols,
        mod->symbols_sz * sizeof(symbol_t)));

  // Set-up sections protection
  for (size_t idx = 0; idx < elf_header.e_shnum; idx++) {
    struct section *section;
    TRY_PTR(section = get_section(mod, idx));
    if (is_allocated(section)) {
      TRY_SYS(mprotect((void *) section->mmap_start, section->mmap_length,
            section->mmap_prot));
    }
  }

  free(section_headers);
  fclose(elf_file);
  return mod;
CATCH:
  free(section_headers);
  if (elf_file) {
    fclose(elf_file);
  }
  module_unload(mod);
  return NULL;
}

void *module_getsym(struct module *mod, const char *name) {
  return (void *) find_symbol(mod, name, ST_NOTYPE | ST_OBJECT | ST_FUNC);
}

void module_unload(struct module *mod) {
  if (mod) {
    free(mod->symbols);
    free(mod->strings);
    for (size_t idx = 0; idx < mod->sections_sz; idx++) {
      dealloc_section(mod->sections + idx);
    }
    free(mod->sections);
    free(mod);
  }
}
