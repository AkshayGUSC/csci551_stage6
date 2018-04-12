#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
// copied ntohs from from http://www.jbox.dk/sanos/source/include/net/inet.h.html
#define convert(n) (((((n) & 0xff)) << 8) | (((n) & 0xff00) >> 8))
//#define convert(n) htons(n)
struct decoded_icmp{
	unsigned int type, code, checksum, id, seqno;
};

void demarshall(unsigned char bytes[8], struct decoded_icmp *out){
	uint16_t arr[6];
	uint8_t type = bytes[0];
	out->type = type;
	uint8_t code = bytes[1];
	out->code = code;
	int k=0;
	for(int i=2;i<8;i++){
		arr[k] = convert(bytes[i]);
		k++;
	}
	out->checksum = (arr[0] << 8) | (arr[1]);
	out->id = (arr[2] << 8) | (arr[3]);
	out->seqno = (arr[4] << 8) | (arr[5]);

	fprintf(stderr, "type = %d\n", out->type);
	fprintf(stderr, "code = %d\n", out->code);
	fprintf(stderr, "checksum = %d\n", out->checksum);
	fprintf(stderr, "id = %d\n", out->id);
	fprintf(stderr, "seqno = %d\n", out->seqno);


}

int main(int argc, char** argv){
	unsigned char sample_bytes[8] = {1,2,3,69,6,120,9,171};
	struct decoded_icmp *out = malloc(sizeof (struct decoded_icmp));
	demarshall(sample_bytes, out);
	free(out);
	exit(0);
}