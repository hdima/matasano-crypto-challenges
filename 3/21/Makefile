NAME=mersenne_twister
RUSTC=rustc

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test_runner: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<

test: test_runner
	./$<

bench: test_runner
	./$< --bench

full_test: ${NAME}
	# Link to the test data:
	# http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.out
	./$< | diff -u mt19937ar.out - && echo "OK"

clean:
	rm -f test_runner ${NAME}

.PHONY: test full_test test_runner bench clean
