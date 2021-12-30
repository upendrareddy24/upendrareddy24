http_downloader: http_downloader.c http_downloader.c
	gcc -o http_downloader http_downloader.c -pthread -L/usr/local/lib/ -lssl  -lcrypto