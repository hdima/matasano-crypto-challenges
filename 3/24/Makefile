NAME=mersenne_twister_cipher
LIB_DIR=../../lib/mersenne_twister
LIB=${LIB_DIR}/libmersenne_twister.rlib
RUSTC=rustc -L ${LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: clean test
