pkcs7: pkcs7.rs
	rustc $<

test: pkcs7.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test pkcs7

.PHONY: test clean
