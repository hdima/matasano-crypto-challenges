NAME=aes_oracle
LIB_NAME=aes_lib
LIB=lib${LIB_NAME}.rlib

${NAME}: ${NAME}.rs ${LIB}
	rustc -L . $<

${LIB}: ${LIB_NAME}.rs
	rustc $<

test_lib: ${LIB_NAME}.rs
	rustc --test -o $@ $<
	./$@

test: ${NAME}.rs ${LIB}
	rustc --test -L . -o $@ $<
	./$@

clean:
	rm -f test test_lib ${NAME} ${LIB}

.PHONY: test clean
