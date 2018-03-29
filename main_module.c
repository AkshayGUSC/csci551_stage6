/*
This is the main module that read a file and based on stages execute corresponding stage code.
*/
#include "main_header.h"

char n_router;
char stage;
int stage_number=0;

int read_file(char *path){

    FILE *fp = fopen(path, "r");
    char buf[100];
    while(!feof(fp)){
        fgets(buf, 100, fp);
        if(buf[0]!='#'){
            if(buf[0] == 's'){
                for(int i=5; i<100;i++){
                    if(buf[i]!=' ' && buf[i]!='\t' && buf[i]!='\n'){
                        stage = buf[i];
                        stage_number = stage -48;
                        printf("Stage = %c\n",stage);
                        break;
                    }
                }   
            }
            else if (buf[0] == 'n'){
                for(int i=11; i<100;i++){
                    if((int)buf[i]>=48 && (int)buf[i]<=57){
                        n_router = buf[i];
                        break;
                    }
                }
                //printf("No. of routers = %c\n", n_router);
            }
            else if((stage_number == 5) || (stage_number ==6)){
                for(int i=12; i<100;i++){
                    if((int)buf[i]>=48 && (int)buf[i]<=57){
                        manitor_hops = buf[i]-48;
                        break;
                    }
                }
            }   
        }
        memset(buf, 0, 100);
    }
    fclose(fp);
    //printf("No. of manitor_hops = %c\n", manitor_hops);

    return (n_router-48);
}

int main(int argc, char** argv)
{
	number_routers = read_file(argv[1]);
    fprintf(stderr,"!!!!!!! STAGE NUMBER = %d !!!!!!!\n", stage_number);
	if(stage_number == 6)
		main_stage6();
	else if(stage_number == 3)
		main_stage3();
	else if(stage_number == 4)
		main_stage4();
	else if(stage_number == 5)
		main_stage5();
	return 0;
} 