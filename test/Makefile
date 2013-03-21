CC          := gcc -m32
CFLAGS      :=
LDFLAGS     := libloader.so

SOURCES     := $(wildcard *.c)
DEPENDS     := $(subst .c,.d,$(SOURCES))
OBJS				:= $(subst .c,.o,$(SOURCES))
MAIN        := $(subst .c,,$(shell grep -l "int main" $(SOURCES)))
TEST_NAME		:= test

all: $(DEPENDS) $(MAIN) $(OBJS)

test: all
	@$(foreach test, $(MAIN), echo ">>> "$(test); ./$(test);)

$(DEPENDS) : %.d : %.c
	$(CC) -MT $(<:.c=.o) -MM $< > $@
	@echo -e "\t"$(CC) -c $(CFLAGS) $< -o $(<:.c=.o) >> $@

$(MAIN) : % : %.o $(patsubst $(TEST_NAME)%, %.o, $@)
	$(CC) $(LDFLAGS) -o $@ $^

-include $(DEPENDS)

clean:
	-rm -f $(DEPENDS) $(MAIN) $(OBJS)

.PHONY: clean test
