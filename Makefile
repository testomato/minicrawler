objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -g -O3 -o $(name) $(objs) -static -lcares -lrt

.odir.stamp:
	mkdir -p o
	touch .odir.stamp

$(objs): o/%.o: %.c .odir.stamp h/struct.h h/proto.h h/global.h h/version.h
	gcc -g -O3 -c -std=gnu99 -o $@ $<

clean:
	rm -f $(objs)
	rm -f .odir.stamp
