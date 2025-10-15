#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

void insertion_sort(int const n, int * const p) {
    for (int i = 1; i < n; i++) {
        int const tmp = p[i];
        int j = i;
        while (j > 0 && p[j-1] > tmp) {
                p[j] = p[j-1];
                j--;
        }
        p[j] = tmp;
    }
}

bool read_number(int *n) {
    char buf[100];
    fgets(buf, sizeof(buf), stdin);
    return sscanf(buf, "%d", n) == 1;
}

int main() {
    int capacity = 10;
    int count = 0;
    int *numbers = malloc(capacity * sizeof(int));

    int n;
    while (read_number(&n)) {
        numbers[count] = n;
        count++;
        if (count > capacity) {
            capacity *= 2;
            numbers = realloc(numbers, capacity * sizeof(int));
        }
    }

    insertion_sort(count, numbers);

    for (int i = 0; i < count; i++) {
        printf("%d\n", numbers[i]);
    }

    return 0;
}