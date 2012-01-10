objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -g -o $(name) $(objs) -lcares

$(objs): o/%.o: %.c h/struct.h h/proto.h h/global.h h/version.h
	gcc -g -c -o $@ $<
