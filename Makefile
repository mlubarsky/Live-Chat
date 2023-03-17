PROG = project05
OBJS = project05.o

%.o: %.c
	gcc -g -c -o $@ $^

$(PROG): $(OBJS)
	gcc -g -o $@ $^

clean:
	rm -rf $(PROG) $(OBJS)
