NAME=single_char_xor_lib
LIB=lib${NAME}.rlib

${LIB}: src/${NAME}.rs
	rustc $<

test: src/${NAME}.rs
	rustc --test -o $@ $<
	./$@

clean:
	rm -f test ${LIB}

.PHONY: test clean
