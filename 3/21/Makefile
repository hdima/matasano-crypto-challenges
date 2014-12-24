NAME=mersenne_twister
LIB_DIR=../../lib/mersenne_twister
LIB=${LIB_DIR}/libmersenne_twister.rlib
RUSTC=rustc -L ${LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: ${NAME}
	# Link to the test data:
	# http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.out
	./$< | diff -u mt19937ar.out - && echo "OK"

clean:
	rm -f ${NAME}

.PHONY: test clean
