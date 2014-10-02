NAME=decrypt_repeating_xor
LIB_NAME=single_char_xor_lib
LIB=lib${LIB_NAME}.rlib

${NAME}: ${NAME}.rs ${LIB}
	rustc -L . $<

${LIB}: ../3/${LIB_NAME}.rs
	rustc --out-dir . $<

test: ${NAME}.rs ${LIB}
	rustc --test -L . -o $@ $<
	./$@

clean:
	rm -f test ${NAME} ${LIB}

.PHONY: test clean
