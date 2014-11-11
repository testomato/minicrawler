headers=$(wildcard src/h/*.h)
objs=$(patsubst src/%.c,o/%.o,$(wildcard src/*.c))
objs-so=$(patsubst o/%.o,so/%.o,$(filter-out o/main.o o/cli.o, $(objs)))

version=0
name=minicrawler
libname=lib$(name).so.3.$(version)

$(name): $(objs)
	gcc -g -O3 -o $(name) $^ -lcares -lssl -lcrypto -lz -luriparser

lib: $(libname)
$(libname): $(objs-so)
	gcc -g -O3 -shared -Wl,-soname,$(libname:.$(version)=) -o $(libname) $^ -lcares -lssl -lcrypto -lz -luriparser

.odir.stamp:
	mkdir -p o
	mkdir -p so
	touch .odir.stamp

o/%.o: src/%.c .odir.stamp $(headers)
	gcc -g -O3 -std=gnu99 -o $@ -c $<

so/%.o: src/%.c .odir.stamp $(headers)
	gcc -g -O3 -std=gnu99 -fpic -o $@ -c $<

install: $(name) $(libname)
	cp $(name) /usr/bin
	test -d /usr/lib/$(name) || mkdir /usr/lib/$(name) && \
		cp $(libname) /usr/lib/$(name) && \
		ldconfig -n /usr/lib/$(name)
	test -d /usr/include/$(name) || mkdir /usr/include/$(name) && \
		cp src/h/minicrawler.h /usr/include/$(name)

clean:
	rm -f $(objs)
	rm -f $(objs-so)
	rm -f .odir.stamp

.PHONY: install clean lib
