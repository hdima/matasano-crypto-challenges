NAME=ecb_cut_paste
LIB_DIR=../../lib/aes
LIB=${LIB_DIR}/libaes_lib.rlib
RUSTC=rustc -L ${LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
