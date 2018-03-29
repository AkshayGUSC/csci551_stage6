all: clean inputs running

inputs:
	gcc -c -Wall router_connection_stage3.c
	gcc -c -Wall router_connection_stage4.c
	gcc -c -Wall router_connection_stage5.c
	gcc -c -Wall router_connection_stage6.c
	gcc -c -Wall main_program_stage3.c
	gcc -c -Wall main_program_stage4.c
	gcc -c -Wall main_program_stage5.c
	gcc -c -Wall main_program_stage6.c
	gcc -c -Wall circuit.c -lcrypto
	gcc -c -Wall circuit_stage5.c -lcrypto
	gcc -c -Wall main_module.c
	gcc -o proja router_connection_stage3.c router_connection_stage4.c router_connection_stage5.c router_connection_stage6.c main_program_stage3.c main_program_stage4.c main_program_stage5.c main_program_stage6.c main_module.c circuit.c circuit_stage5.c -lcrypto 

running:
	sudo ./proja file

clean:
	rm -rf proja *.o *.out

.PHONY: running clean
