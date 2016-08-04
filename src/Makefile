All:
	@cd libevent_cyassl && mkdir -p lib && make && cp lib/* ../../lib/ && make clean && cd ..
	@cd demo && mkdir -p bin && make && cp bin/* ../../bin/ && make clean && cd ..

.PHONY:clean
clean:
	rm -rf ../bin/*
	rm -rf ../lib/*
