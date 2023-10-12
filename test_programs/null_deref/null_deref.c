#include <stdio.h>

void my_fun(int *num) {
	*num = 42;
}

int main(int argc, char *argv[]) {
	int my_num;
	my_fun(&my_num);
	printf("my_num: %d\n", my_num);
	return 0;
}