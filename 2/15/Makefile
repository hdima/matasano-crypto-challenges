NAME=pkcs7_validation
RUSTC=rustc

${NAME}: src/${NAME}.rs
	${RUSTC} $<

test: src/${NAME}.rs
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
