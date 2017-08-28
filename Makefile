all: nfqnl_test

nfqnl_test: nfqnl_test.cpp filter_lists.txt
	g++ -W -Wall -o nfqnl_test nfqnl_test.cpp -lnetfilter_queue

clean:
	rm nfqnl_test
