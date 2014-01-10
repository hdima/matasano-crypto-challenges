aes_ecb_decrypter: aes_ecb_decrypter.rs
	rustc $<

test: aes_ecb_decrypter.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test aes_ecb_decrypter

.PHONY: test clean
