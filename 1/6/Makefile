decrypt_repeating_xor: decrypt_repeating_xor.rs libsingle_char_xor_lib-*.so
	rustc -L . $<

libsingle_char_xor_lib-*.so: ../3/single_char_xor_lib.rs
	rustc --out-dir . $<

test: decrypt_repeating_xor.rs libsingle_char_xor_lib-*.so
	rustc --test -L . -o test $<
	./test

clean:
	rm -f test decrypt_repeating_xor libsingle_char_xor_lib-*.so

.PHONY: test clean
