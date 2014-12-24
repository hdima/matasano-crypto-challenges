NAME=mersenne_twister
LIB=lib${NAME}.rlib
RUSTC=rustc

${LIB}: src/${NAME}.rs
	${RUSTC} $<

test_runner: src/${NAME}.rs
	${RUSTC} --test -o $@ $<

test: test_runner
	./$<

bench: test_runner
	./$< --bench

clean:
	rm -f test_runner ${LIB}

.PHONY: test test_runner bench clean
