NAME=crack_mersenne_twister
LIB_DIR=../../lib/mersenne_twister
LIB=${LIB_DIR}/libmersenne_twister.rlib
RUSTC=rustc -L ${LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

clean:
	rm -f ${NAME}

.PHONY: clean
