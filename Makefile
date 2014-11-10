objs=$(patsubst src/%.c,o/%.o,$(wildcard src/*.c))

name=minicrawler

$(name): $(objs)
	gcc -g -O3 -o $(name) $(objs) -lcares -lssl -lcrypto -lz -luriparser

lib: $(objs)
	gcc -g -O3 -shared -o lib$(name).so $(objs) -lcares -lssl -lcrypto -lz -luriparser

.odir.stamp:
	mkdir -p o
	touch .odir.stamp

$(objs): o/%.o: src/%.c .odir.stamp src/h/struct.h src/h/proto.h src/h/version.h
	gcc -g -O3 -std=gnu99 -fpic -o $@ -c $<

clean:
	rm -f $(objs)
	rm -f .odir.stamp
