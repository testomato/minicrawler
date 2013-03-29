objs=$(patsubst %.c,o/%.o,$(wildcard *.c))

name=minicrawler

$(name): $(objs)
	gcc -g -O3 -o $(name) $(objs) -static -lcares -lrt -lssl

.odir.stamp:
	mkdir -p o
	touch .odir.stamp

$(objs): o/%.o: %.c .odir.stamp h/struct.h h/proto.h h/version.h
	gcc -g -O3 -std=gnu99 -o $@ -c $<

clean:
	rm -f $(objs)
	rm -f .odir.stamp
