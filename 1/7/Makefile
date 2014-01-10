aes_ecb: aes_ecb.rs
	rustc $<

test: aes_ecb.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test aes_ecb

.PHONY: test clean
