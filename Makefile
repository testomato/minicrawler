objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -lcares -o $(name) $(objs)

$(objs): o/%.o: %.c
	gcc -c -o $@ $<
