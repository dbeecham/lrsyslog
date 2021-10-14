#######################
# USING THIS MAKEFILE #
#######################
# 
# * set default target
# * set test_driver target
# * set install target
# * set clean target


#########################################
# VARIABLES - overridable by make flags #
#########################################
# {{{

# Stuff to set in CFLAGS:
#   -march=native
#       speed! Don't use for cross compilation.
#   -fpie -Wl,-pie
#       don't use along with -fPIE and -shared for shared libraries
CFLAGS         = -Iinclude -Iinc -Isrc -Wall -Wextra -Wno-unused-variable \
                 -Wno-implicit-fallthrough -Wno-unused-const-variable \
                 -std=c11 -O1 -g3 -D_FORTIFY_SOURCE=2 -fexceptions \
                 -fasynchronous-unwind-tables -fpie -Wl,-pie \
                 -fstack-protector-strong -grecord-gcc-switches \
                 -Werror=format-security \
                 -Werror=implicit-function-declaration -Wl,-z,defs -Wl,-z,now \
                 -Wl,-z,relro -pthread $(EXTRA_CFLAGS)
LDFLAGS        = -O0 -g3 $(EXTRA_LDFLAGS)
LDLIBS         = -pthread $(EXTRA_LDLIBS)
DESTDIR        = /
PREFIX         = /usr/local
RAGEL          = ragel
RAGELFLAGS     = -G2 $(EXTRA_RAGELFLAGS)
INSTALL        = install
BEAR           = bear
COMPLEXITY     = complexity
CFLOW          = cflow
SED            = sed
NEATO          = neato
CTAGS          = ctags
SCAN_BUILD     = scan-build
Q              = @
CC_COLOR       = \033[0;34m
LD_COLOR       = \033[0;33m
TEST_COLOR     = \033[0;35m
INSTALL_COLOR  = \033[0;32m
NO_COLOR       = \033[m

# }}}


###############
# MAIN TARGET #
###############
# {{{

default: all

all: lsyslog

lsyslog: lsyslog.o lsyslog_tcp_task.o lsyslog_nats_task.o lsyslog_client_parser.o nats_parser.o gwy01_parser.o

# }}}


#########################
# DEVELOPMENT UTILITIES #
#########################
# {{{

.PHONY: complexity
complexity:
	$(COMPLEXITY) --scores --threshold=1 src/*.c

.PHONY: ci
ci: | cscope.files
	cat cscope.files | entr sh -c "clear; make -B"

.PHONY: ci-test
ci-test: | cscope.files
	cat cscope.files | entr sh -c "clear; make -B test"

.PHONY: cscope
cscope: | cscope.files
	cscope -b -q -k

.PHONY: compile_commands.json
compile_commands.json:
	$(BEAR) $(MAKE) -B all

.PHONY: tags
tags: | cscope.files
	$(CTAGS) -L cscope.files

.PHONY: scan-build
scan-build:
	$(SCAN_BUILD) $(MAKE) -B all

# }}}


################
# TEST TARGETS #
################
# {{{

# The 'test' target is primarily for running a separate test suite, usually
# for unit tests and property based testing. It differs from the 'check'
# target in that it does not necessarily need the compiled target (the
# library or binary that this Makefile builds) - it only needs some
# of the object files. Most users will make a project by naively running
# 'make' in the directory, and then run 'make test' -  but in 'make test',
# we'd like to enable code coverage and other neat stuff using CFLAGS and
# LDLIBS. I've taken the liberty to assume that this Makefile will be used
# in projects where a full recompile isn't a big deal, and we just recompile
# the entire project with the correct compile flags. Then we have the opposite
# problem, that the user might run 'make install' after a 'make test'; that
# won't be *as much* of an issue - at least the target binary will not be
# linked with the '--coverage' flag, and it won't generate gcov files when
# executed.
test: CFLAGS += -I./vendor/munit/ -fprofile-arcs -ftest-coverage
test: LDLIBS += -lgcov --coverage
test: test_driver
	@printf "$(TEST_COLOR)TEST$(NO_COLOR) $@\n"
	$(Q)./test_driver \
		&& gcov src/*.c src/*.c.rl \
		&& gcovr -r . -e ".*munit.c" -e "tests/test.*.c"


# The 'check' target is primarily for testing *the compiled target*; i.e. if
# you're building a shared library, the 'check' target would compile a binary
# which links to that shared library and runs tests. If you're building a
# binary, then this target would in some useful way execute that file and test
# it's behaviour.
check:
	@echo "No checks available."


test_driver: CFLAGS += -Ivendor/munit/
test_driver: test_driver.o lsyslog_client_parser.o

# }}}


###################
# INSTALL TARGETS #
###################
# {{{
#
# Examples:
#
#   install: $(DESTDIR)$(PREFIX)/lib/libgwy.so $(DESTDIR)$(PREFIX)/include/libgwy.h
#
#   install: $(DESTDIR)/bin/cnatsd
#

install: $(DESTDIR)$(PREFIX)/bin/lsyslog

# }}}


#################
# CLEAN TARGETS #
#################
# {{{

clean:
	rm -f *.o test_driver *.gcda *.gcno *.gcov *.cflow *deps lsyslog_client_parser.c

distclean: clean
	rm -f *.so lsyslog

# }}}


########
# DOCS #
########
# {{{

.PHONY: docs
docs:
	$(MAKE) -C docs $@

.PHONY: latexpdf
latexpdf:
	$(MAKE) -C docs $@

# }}}


################
# SOURCE PATHS #
################
# {{{

vpath %.c src/
vpath %.c.rst src/
vpath %.c.md src/
vpath %.c.rl src/
vpath %.c.rl.md src/
vpath %.c.rl.rst src/
vpath %.h include/
vpath %.h inc/
vpath munit.c vendor/munit/
vpath test_%.c tests/

# }}}


##################
# IMPLICIT RULES #
##################
# {{{

$(DESTDIR)$(PREFIX)/bin:
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0755 -d $@

$(DESTDIR)$(PREFIX)/lib:
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0755 -d $@

$(DESTDIR)$(PREFIX)/include:
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0755 -d $@

$(DESTDIR)$(PREFIX)/lib/%.so: %.so | $(DESTDIR)$(PREFIX)/lib
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0644 $< $@

$(DESTDIR)$(PREFIX)/lib/%.a: %.a | $(DESTDIR)$(PREFIX)/lib
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0644 $< $@

$(DESTDIR)$(PREFIX)/include/%.h: %.h | $(DESTDIR)$(PREFIX)/include
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0644 $< $@

$(DESTDIR)$(PREFIX)/bin/%: % | $(DESTDIR)$(PREFIX)/bin
	@printf "$(INSTALL_COLOR)INSTALL$(NO_COLOR) $@\n"
	$(Q)$(INSTALL) -m 0755 $< $@

%.deps: %
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) -M $^ | $(SED) -e 's/[\\ ]/\n/g' | $(SED) -e '/^$$/d' -e '/\.o:[ \t]*$$/d' | sort | uniq > $@

%: %.o
	@printf "$(LD_COLOR)LD$(NO_COLOR) $@\n"
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)

%.a:
	@printf "$(LD_COLOR)LD$(NO_COLOR) $@\n"
	$(Q)$(AR) rcs $@ $^

%.so: CFLAGS += -fPIC
%.so:
	@printf "$(LD_COLOR)LD$(NO_COLOR) $@\n"
	$(Q)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LOADLIBES) $(LDLIBS)

%.o: %.c
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $^

# UPX-minified binaries
%.upx: %
	@printf "$(LD_COLOR)UPX$(NO_COLOR) $@\n"
	$(Q)$(UPX) -o $@ $^

%.stripped: %
	@printf "$(LD_COLOR)STRIP$(NO_COLOR) $@\n"
	$(Q)$(STRIP) -o $@ $^

# for each c file, it's possible to generate a cflow flow graph.
%.c.cflow: %.c
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(CFLOW) -o $@ $<

# from dot graphs, neato can generate png files
%.png: %.dot
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(NEATO) -Tpng -Ln100 -o $@ $<

# ragel can generate dot graphs
%.dot: %.rl
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(RAGEL) $(RAGELFLAGS) -V -p $< -o $@

# ragel compiles c.rl files to .c files
%.c: %.c.rl
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)$(RAGEL) -Iinclude $(RAGELFLAGS) -o $@ $<

# untangle .rst files into c files
%.c: %.c.rst
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)cat $< | rst_tangle > $@

# build c files from markdown files - literate programming style
%.c: %.c.md
	@printf "$(CC_COLOR)CC$(NO_COLOR) $@\n"
	$(Q)cat $< | $(SED) -n '/^```c/,/^```/ p' | $(SED) '/^```/ d' > $@

# }}}

#vim: set foldmethod=marker
