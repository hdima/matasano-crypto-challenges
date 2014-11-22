NAME=pkcs7
RUSTC=rustc

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
