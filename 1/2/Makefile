fixed_xor: fixed_xor.rs
	rustc $<

test: fixed_xor.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test fixed_xor

.PHONY: test clean
