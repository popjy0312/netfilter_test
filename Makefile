all: nfqnl_test

nfqnl_test: nfqnl_test.c filter_lists.txt
	gcc -W -Wall -o nfqnl_test nfqnl_test.c -lnetfilter_queue

clean:
	rm nfqnl_test
