#include <stdio.h>
#include <stdlib.h>

int averageArray(int A[]) {
        int sum = 0;
        int len = 0;

        for (int i = 0; A[i] != -460; i++) {
            sum = sum + A[i];
            len++;
        }

        return sum / len;
}

void scan_temperatures(FILE *file) {
    int n0, n1, n2, n3, A[5];

    A[4] = -460; //terminating value - just below zero kelvin

    while(fscanf(file, "%d %d %d %d", &n0, &n1, &n2, &n3) == 4) {
        A[0] = n0;
        A[1] = n1;
        A[2] = n2;

        if (averageArray(A) > 100) {
            printf("It's too darn hot!\n");
        }
    }
}

int main(void) {

    FILE *file = fopen("data.txt","r");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    scan_temperatures(file);

    return EXIT_SUCCESS;
}
