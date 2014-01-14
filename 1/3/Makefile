single_char_xor: single_char_xor.rs libsingle_char_xor_lib-*.so
	rustc -L . $<

libsingle_char_xor_lib-*.so: single_char_xor_lib.rs
	rustc $<

test: single_char_xor_lib.rs
	rustc --test -L . -o test $<
	./test

clean:
	rm -f test single_char_xor libsingle_char_xor_lib-*.so

.PHONY: test clean
