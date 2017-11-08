all: nfqnl_test

nfqnl_test: nfqnl_test.cpp filter_lists.txt
	g++ -o nfqnl_test nfqnl_test.cpp -lnetfilter_queue -Wall

clean:
	rm nfqnl_test
