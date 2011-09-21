objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -lcares -o $(name) $(objs)

$(objs): o/%.o: %.c h/struct.h h/proto.h h/global.h h/version.h
	gcc -c -o $@ $<
