objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -g -O3 -o $(name) $(objs) -static -lcares -lrt

$(objs): o/%.o: %.c h/struct.h h/proto.h h/global.h h/version.h
	gcc -g -O3 -c -std=gnu99 -o $@ $<
