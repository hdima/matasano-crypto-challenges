find_ecb_encrypted: find_ecb_encrypted.rs
	rustc $<

test: find_ecb_encrypted.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test find_ecb_encrypted

.PHONY: test clean
