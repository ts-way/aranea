all:
	gcc -Wall -O3 -o aranea aranea.c -lpcap -lresolv -pthread

clean:
	rm aranea

