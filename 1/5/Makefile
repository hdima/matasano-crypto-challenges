repeating_xor: repeating_xor.rs
	rustc $<

test: repeating_xor.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test repeating_xor

.PHONY: test clean
