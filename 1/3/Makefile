single_xor: single_xor.rs
	rustc $<

test: single_xor.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test single_xor

.PHONY: test clean
