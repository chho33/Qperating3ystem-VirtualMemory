#include <stdio.h>

int main(int argc, char* argv[]){

	unsigned long start = 0x7f4d18547000;
	unsigned long end   = 0x7f4d1872e000;
	unsigned long num_page = (end - start) >> 12;
	unsigned long num_pmd  = ((end >> 21) - (start >> 21));
	unsigned long num_pud  = ((end >> 30) - (start >> 30));
	unsigned long num_p4d  = ((end >> 39) - (start >> 39)); 
	unsigned long num_pgd  = ((end >> 39) - (start >> 39)); 
	

	if (end % (1 << 12))
		num_page++;
	if (end % (1 << 21))
		num_pmd++;
	if (end % (1 << 30))
		num_pud++;
	if (end % ((unsigned long)1 << 39))
		num_p4d++;
	if (end % ((unsigned long)1 << 39))
		num_pgd++;
	// max_pgd_index;

	


	printf("%lx\n", num_page);
	printf("%lx\n", num_pmd);
	printf("%lx\n", num_pud);
	printf("%lx\n", num_p4d);
	printf("%lx\n", num_pgd);

	return 0;
}
