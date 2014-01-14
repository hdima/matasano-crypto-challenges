find_single_char_xor: find_single_char_xor.rs libsingle_char_xor_lib-*.so
	rustc -L . $<

libsingle_char_xor_lib-*.so: ../3/single_char_xor_lib.rs
	rustc --out-dir . $<

test:

clean:
	rm -f test find_single_char_xor libsingle_char_xor_lib-*.so

.PHONY: test clean
