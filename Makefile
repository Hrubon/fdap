#
# Makefile for the FDAP suite of tools and libraries
#
# Ondřej Hrubý <o@hrubon.cz> (c) 2018
# 
# Automatic dependencies based on [1].
#
# [1] http://make.mad-scientist.net/papers/advanced-auto-dependency-generation
#

.SILENT:
.PHONY: default dev clean debug tests doc stats

default: dev

#
# Directory layout
#

SRC_DIR := src
INC_DIR := $(SRC_DIR)/include
TEST_DIR := tests
BUILD_DIR := build
BISON_DIR := $(BUILD_DIR)/bison
FLEX_DIR := $(BUILD_DIR)/flex
DEPS_DIR := $(BUILD_DIR)/deps
TEST_BINS_DIR := $(BUILD_DIR)/tests

#
# Target definitions, main compiler and linker flags
#

BINS := fdapd fdapdiag
NSS_LIBS := libnss_fdap.so
PAM_LIBS := pam_fdap.so
LIBS := $(NSS_LIBS) $(PAM_LIBS)

CFLAGS += -std=gnu11 \
	-Wall -Wextra -Werror --pedantic \
	-Wno-unused-function -Wno-variadic-macros -Wimplicit-fallthrough=3 \
	-I $(INC_DIR) -I$(BISON_DIR)
LDFLAGS += -Wall \
	-l:libmbedtls.a -l:libmbedx509.a -l:libmbedcrypto.a

MODULES := \
	build/bison/fdapc_cfg_parser \
	build/bison/fdapd_cfg_parser \
	build/bison/filter_parser \
	build/flex/fdapc_cfg_lexer \
	build/flex/fdapd_cfg_lexer \
	build/flex/filter_lexer \
	src/array \
	src/aname \
	src/cbor \
	src/cfg \
	src/diag \
	src/except \
	src/fdap \
	src/filter \
	src/index \
	src/iter \
	src/iobuf \
	src/iobuf_sock \
	src/iobuf_str \
	src/iobuf_tls \
	src/keystore \
	src/list \
	src/log \
	src/memory \
	src/mempool \
	src/objpool \
	src/record \
	src/request \
	src/socket \
	src/storage \
	src/storage-dummy \
	src/storage-local \
	src/strbuf \
	src/timeout \
	src/tls \
	src/token_table \
	src/trie \

PIC_MODULES := \
	build/bison/fdapc_cfg_parser \
	build/bison/fdapd_cfg_parser \
	build/bison/filter_parser \
	build/flex/fdapc_cfg_lexer \
	build/flex/fdapd_cfg_lexer \
	build/flex/filter_lexer \
	src/array \
	src/aname \
	src/cbor \
	src/cfg \
	src/diag \
	src/except \
	src/fdap \
	src/filter \
	src/index \
	src/iter \
	src/iobuf \
	src/iobuf_sock \
	src/iobuf_str \
	src/iobuf_tls \
	src/keystore \
	src/list \
	src/log \
	src/memory \
	src/mempool \
	src/objpool \
	src/record \
	src/request \
	src/socket \
	src/storage \
	src/storage-dummy \
	src/storage-local \
	src/strbuf \
	src/timeout \
	src/tls \
	src/token_table \
	src/trie \

#
# Auto-generated dependencies
#

%.d: ;
.PRECIOUS: %.d
DEPFLAGS = -MT $@ -MMD -MP -MF $(patsubst %.o,%.d,$@)

#
# Bison and Flex generated files
#

$(BISON_DIR)/%.c: $(SRC_DIR)/%.y Makefile
	echo "BISON    $*"
	mkdir -p $(@D)
	bison --defines=$(BISON_DIR)/$*.h -o $@ $<

$(BISON_DIR)/%.h: $(BISON_DIR)/%.c ;

$(FLEX_DIR)/%.c: $(SRC_DIR)/%.l Makefile
	echo "FLEX     $*"
	mkdir -p $(@D)
	flex -o $@ $<

.PRECIOUS: $(FLEX_DIR)/%.c

#
# Documentation
#

DOC_DIR := $(BUILD_DIR)/doc
APIDOC_DIR := apidoc/
DOC_INSTALL_DIR := ../text/$(APIDOC_DIR)
DOC_TEX := $(DOC_DIR)/doc.tex
DOC_LOCAL_TEX := $(DOC_DIR)/doc-local.tex
DOC_PDF := $(DOC_DIR)/doc-local.pdf
DOC_SRCS := \
	cbor.c.tex \
	fdapd.c.tex \
	include/array.h.tex \
	include/cbor.h.tex \
	include/iobuf.h.tex \
	include/keystore.h.tex \
	include/log.h.tex \
	include/objpool.h.tex \
	include/storage.h.tex \
	include/record.h.tex \
	include/strbuf.h.tex \
	include/timeout.h.tex \
	include/tls.h.tex \
	include/trie.h.tex \
	timeout.c.tex \
	trie.c.tex \

DOC_FILES := $(addprefix $(DOC_DIR)/,$(DOC_SRCS))
DOC_INSTALL_FILES := $(addprefix apidoc/,$(DOC_SRCS))

$(DOC_DIR)/%.tex: $(SRC_DIR)/% Makefile
	echo "MAKEDOC $*"
	mkdir -p $(@D)
	./makedoc.py $< >$@

$(DOC_TEX): $(DOC_FILES) doc-intro.tex doc-outro.tex Makefile
	echo "MAKEDOC $*"
	cat doc-intro.tex >$@
	for file in $(DOC_INSTALL_FILES); do echo "\\input{$$file}" >>$@; done
	cat doc-outro.tex >>$@

$(DBG_FDAPC_LIB): $(DBG_PIC_OBJS)
	echo "STATIC   $*"
	mkdir -p $(@D)
	ar rcs $@ $^

$(DOC_LOCAL_TEX): $(DOC_FILES) doc-intro.tex doc-outro.tex Makefile
	echo "MAKEDOC $*"
	cat doc-intro-local.tex >$@
	for file in $(DOC_SRCS); do echo "\\input{$$file}" >>$@; done
	cat doc-outro-local.tex >>$@

$(DOC_PDF): $(DOC_LOCAL_TEX)
	echo "PDFLATEX  $*"
	pdflatex -output-directory $(DOC_DIR) $(DOC_LOCAL_TEX) 2>/dev/null >/dev/null

#
# Debug
#

DBG_DIR := $(BUILD_DIR)/dbg
DBG_BIN_DIR := $(DBG_DIR)/bin
DBG_OBJ_DIR := $(DBG_DIR)/obj
DBG_PIC_DIR := $(DBG_DIR)/pic
DBG_LIB_DIR := $(DBG_DIR)/libs

DBG_CFLAGS := $(CFLAGS) -ggdb3
DBG_PIC_CFLAGS := $(DBG_CFLAGS) -fPIC
DBG_LDFLAGS := $(LDFLAGS)# -fsanitize=address 
DBG_SHARED_FLAGS += $(DBG_LDFLAGS) -shared -Wl,-soname,$@

DBG_BINS := $(addprefix $(DBG_BIN_DIR)/,$(BINS))
DBG_NSS_LIBS := $(addprefix $(DBG_LIB_DIR)/,$(NSS_LIBS))
DBG_PAM_LIBS := $(addprefix $(DBG_LIB_DIR)/,$(PAM_LIBS))
DBG_FDAPC_LIB := $(DBG_LIB_DIR)/libfdapc.a
DBG_LIBS := $(DBG_NSS_LIBS) $(DBG_PAM_LIBS) $(DBG_FDAPC_LIB)
DBG_OBJS := $(addprefix $(DBG_OBJ_DIR)/,$(MODULES:%=%.o))
DBG_PIC_OBJS := $(addprefix $(DBG_PIC_DIR)/,$(PIC_MODULES:%=%.o))

$(DBG_BIN_DIR)/%: $(DBG_OBJS) $(DBG_OBJ_DIR)/src/%.o
	echo "BIN      $*"
	mkdir -p $(@D)
	$(CC) $^ $(DBG_LDFLAGS) -o $@ -fsanitize=address

$(DBG_LIB_DIR)/%.so: $(DBG_PIC_OBJS) $(DBG_PIC_DIR)/src/%.o
	echo "SHARED   $*"
	mkdir -p $(@D)
	$(CC) $^ $(DBG_SHARED_FLAGS) -lpam -o $@

$(DBG_FDAPC_LIB): $(DBG_PIC_OBJS)
	echo "STATIC   $*"
	mkdir -p $(@D)
	ar rcs $@ $^

$(DBG_OBJ_DIR)/%.o: %.c $(DBG_OBJ_DIR)/%.d Makefile
	echo "OBJ+DEPS $*"
	mkdir -p $(@D)
	$(CC) -c $(DBG_CFLAGS) $(DEPFLAGS) -o $@ -fsanitize=address $<

$(DBG_PIC_DIR)/%.o: %.c $(DBG_PIC_DIR)/%.d Makefile
	echo "PIC+DEPS $*"
	mkdir -p $(@D)
	$(CC) -c $(DBG_PIC_CFLAGS) $(DEPFLAGS) -o $@ $<

#
# Tests
#

TEST_UNITS := \
	array/drop \
	array/pop \
	array/push \
	cbor/array \
	cbor/bytes \
	cbor/error \
	cbor/ints \
	cbor/item \
	cbor/map \
	cbor/sval \
	cbor/tags \
	cbor/text \
	cbor/uints \
	cfg/fdapc_parser \
	cfg/fdapd_parser \
	diag/build \
	diag/diag \
	filter/aname \
	filter/build \
	filter/match \
	filter/escape \
	filter/parser \
	iobuf/iobuf_str/peek \
	iobuf/rlimit \
	iobuf/rw \
	keystore/all \
	storage/random \
	storage/record \
	timeout/main \
	trie/english \

TEST_BINS := $(addprefix $(TEST_BINS_DIR)/, $(TEST_UNITS))

$(TEST_BINS_DIR)/%: $(DBG_OBJS) $(DBG_OBJ_DIR)/$(TEST_DIR)/%.o
	echo "BIN      $*"
	mkdir -p $(@D)
	$(CC) $^ $(DBG_LDFLAGS) -o $@ -fsanitize=address

.PRECOUS: $(DBG_OBJ_DIR)/$(TEST_DIR)/%.o

#
# Install targets
#
INSTALL_NSS_LIBS := $(addprefix /lib/,$(addsuffix .2,$(NSS_LIBS)))
INSTALL_PAM_LIBS := $(addprefix /lib/security/,$(PAM_LIBS))
CONF_DIR := conf/
INSTALL_CONF_DIR := /etc/fdap/

install-libs: $(DBG_LIBS)
	install $(DBG_NSS_LIBS) $(INSTALL_NSS_LIBS)
	install $(DBG_PAM_LIBS) $(INSTALL_PAM_LIBS)

install-conf: $(CONF_DIR)
	rm -rf -- $(INSTALL_CONF_DIR)
	mkdir $(INSTALL_CONF_DIR)
	cp -r $(CONF_DIR)* $(INSTALL_CONF_DIR)

install: install-libs install-conf

#
# Finale grandioso
#

dev: $(DBG_BINS)

debug: $(DBG_BINS) $(DBG_LIBS) doc tests

tests: $(TEST_BINS)
	./run-tests.sh "$(TEST_BINS)" 2>/dev/null

clean: 
	rm -rf -- $(BUILD_DIR)

doc: $(DOC_PDF)
	
docinstall: $(DOC_TEX)
	rm -rf $(DOC_INSTALL_DIR)
	cp -f -r $(DOC_DIR) $(DOC_INSTALL_DIR)

stats:
	find $(SRC_DIR) $(TEST_DIR) -name "*.c" -or -name "*.h" -or -name "*.y" -or -name "*.l" \
		| xargs cat \
		| wc -lc

include $(shell find . -type f -name "*.d")
