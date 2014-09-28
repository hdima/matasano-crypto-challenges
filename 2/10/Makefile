NAME=aes_cbc

${NAME}: ${NAME}.rs
	rustc $<

test: ${NAME}.rs
	rustc --test -o test $<
	./test

clean:
	rm -f test ${NAME}

.PHONY: test clean
