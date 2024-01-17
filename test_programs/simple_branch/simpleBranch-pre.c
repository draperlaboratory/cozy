#include <stdio.h>


int main(int v) {

}

int bv1();
int bv2();

int my_fun(int v) {
    if (v < 10) return bv1();
    puts("you're not on branch 1");
    if (v < 15) return bv2();
    puts("you're not on branch 2");
    puts("you're on the catchall return");
    return 0;
}

int bv1() {
    puts("you're on branch 1");
    return 1;
}

int bv2() {
    puts("you're on branch 2");
    return 2;
}
