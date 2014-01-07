single_xor: single_xor.rs libsingle_xor_lib-*.so
	rustc -L . $<

libsingle_xor_lib-*.so: single_xor_lib.rs
	rustc $<

test: single_xor.rs libsignle_xor_lib-*.so
	rustc --test -L . -o test $<
	./test

clean:
	rm -f test single_xor libsingle_xor_lib-*.so

.PHONY: test clean
