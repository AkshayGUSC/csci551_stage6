all: clean inputs running

inputs:
	gcc -c -Wall router_connection.c
	gcc -c -Wall proxy_connection.c
	gcc -c -Wall main_program_3.c
	gcc -c -Wall input_identification.c
	gcc -c -Wall circuit.c -lcrypto
	gcc -o proja input_identification.c proxy_connection.c router_connection.c main_program_3.c circuit.c -lcrypto 

running:
	sudo ./proja file

clean:
	rm -rf proja *.o *.out

.PHONY: running clean
