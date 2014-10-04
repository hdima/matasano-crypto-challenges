NAME=find_ecb_encrypted

${NAME}: ${NAME}.rs
	rustc $<

test: ${NAME}.rs
	rustc --test -o $@ $<
	./$@

clean:
	rm -f test ${NAME}

.PHONY: test clean
