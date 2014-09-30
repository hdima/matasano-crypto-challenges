NAME=single_char_xor
LIB_NAME=single_char_xor_lib
LIB=lib${LIB_NAME}.rlib

${NAME}: ${NAME}.rs ${LIB}
	rustc -L . $<

${LIB}: ${LIB_NAME}.rs
	rustc $<

test: ${LIB_NAME}.rs
	rustc --test -L . -o $@ $<
	./$@

clean:
	rm -f test ${NAME} ${LIB}

.PHONY: test clean
