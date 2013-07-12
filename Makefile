NGX_VER = 1.4.1

NGX_DISTR_BASE_URL = http://nginx.org/download
NGX_DIR = nginx-$(NGX_VER)
NGX_TAR = $(NGX_DIR).tar.gz
NGX_DISTR_URL = $(NGX_DISTR_BASE_URL)/$(NGX_TAR)
DISTR_BASE_PATH = distr
NGX_TAR_PATH = $(DISTR_BASE_PATH)/$(NGX_TAR)
NGX_SRC_PATH = src/nginx

PREFIX = /usr/local/nginx
RUN_PATH = run

WGET = wget
MKDIR = mkdir
TAR = tar

ifneq "$(NB)" "1"
GDB_BREAK = $(addprefix -ex 'b ,$(addsuffix ',$B))
endif

GDB_FLAGS = -ex "set breakpoint pending on" \
			-ex "set follow-fork-mode child" \
			-ex "handle SIGPIPE nostop" \
			-ex "handle SIGHUP nostop" \
			"set detach-on-fork on"
GDB_RUN = -ex r

.PHONY: src clean getsrc debug run

all: build

getsrc:
	[ -d $(DISTR_BASE_PATH) ] || $(MKDIR) -p $(DISTR_BASE_PATH)
	[ -f $(NGX_TAR_PATH) ] || $(WGET) $(NGX_DISTR_URL) -O $(NGX_TAR_PATH)

src: 
	@if test -d $(NGX_SRC_PATH); then \
		echo "source dir \"$(NGX_SRC_PATH)\" exists!"; \
	else \
		$(MKDIR) -p $(NGX_SRC_PATH); \
		$(TAR) xzf $(NGX_TAR_PATH) --strip-components=1 -C $(NGX_SRC_PATH); \
	fi

build:
	@if test ! -d $(NGX_SRC_PATH); then \
		echo -e "source dir \"$(NGX_SRC_PATH)\" not exists.\nTry: make getsrc && make src"; exit 1; \
	fi
	cd $(NGX_SRC_PATH) \
		&& make

build_all:
	@if test ! -d $(NGX_SRC_PATH); then \
		echo -e "source dir \"$(NGX_SRC_PATH)\" not exists.\nTry: make getsrc && make src"; exit 1; \
	fi
	cd $(NGX_SRC_PATH) \
		&& CFLAGS="-g -O0 -W -Wall -Wno-unused-parameter -Werror" ./configure \
			--without-http_auth_basic_module \
			--add-module=../.. \
			--with-debug \
		&& $(MAKE)

install:
	cd $(NGX_SRC_PATH) && $(MAKE) install

runenv:
	mkdir -p $(RUN_PATH)/logs
	[ -d $(RUN_PATH)/html ] || cp -r html $(RUN_PATH)
	[ -d $(RUN_PATH)/conf ] || cp -r conf $(RUN_PATH)

run: runenv
	cd $(RUN_PATH) && \
		../$(NGX_SRC_PATH)/objs/nginx -p .

debug: runenv
	cd $(RUN_PATH) && \
		gdb $(GDB_FLAGS) $(GDB_BREAK) $(GDB_RUN) --args ../$(NGX_SRC_PATH)/objs/nginx -p .

clean:
	rm -rf $(NGX_SRC_PATH) $(RUN_PATH) tags

clean_all: clean
	rm -rf $(DISTR_BASE_PATH)
	
