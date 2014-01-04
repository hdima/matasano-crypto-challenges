hex_base64: hex_base64.rs
	rustc $<

test: hex_base64.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test hex_base64

.PHONY: test clean
