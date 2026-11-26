APXS ?= apxs
CFLAGS_WARN = -Wall -Wextra -Wno-unused-parameter -Werror

.PHONY: all install clean

all: .libs/mod_schiza.so

.libs/mod_schiza.so: mod_schiza.c
	$(APXS) -c -Wc,"$(CFLAGS_WARN)" mod_schiza.c

# Copies the module to the Apache modules directory (needs root)
install: all
	$(APXS) -i -n schiza .libs/mod_schiza.so

clean:
	rm -rf .libs *.la *.lo *.slo *.o
