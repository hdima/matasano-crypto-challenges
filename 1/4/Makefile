find_single_xor: find_single_xor.rs libsingle_xor_lib-*.so
	rustc -L . $<

libsingle_xor_lib-*.so: ../3/single_xor_lib.rs
	rustc --out-dir . $<

test: find_single_xor.rs libsingle_xor_lib-*.so
	rustc --test -L . -o test $<
	./test

clean:
	rm -f test find_single_xor libsingle_xor_lib-*.so

.PHONY: test clean
