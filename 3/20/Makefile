NAME=fixed_nonce_ctr
AES_LIB_DIR=../../lib/aes
XOR_LIB_DIR=../../lib/single_char_xor
LIB_DIR=${AES_LIB_DIR} ${XOR_LIB_DIR}
LIB=${AES_LIB_DIR}/libaes_lib.rlib ${XOR_LIB_DIR}/libsingle_char_xor_lib.rlib
RUSTC=rustc -L ${AES_LIB_DIR} -L ${XOR_LIB_DIR}

${NAME}: src/${NAME}.rs ${LIB}
	${RUSTC} $<

test: src/${NAME}.rs ${LIB}
	${RUSTC} --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
