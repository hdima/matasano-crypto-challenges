NAME=find_single_char_xor
LIB_DIR=../../lib/single_char_xor
LIB=${LIB_DIR}/libsingle_char_xor_lib.rlib
RUSTC=rustc -L ${LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
