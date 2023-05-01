#include "testlib.hpp"
#include <iostream>
#include <cstdlib>
#include <time.h>
using namespace std;

void print_num()
{
    srand(time(0));
    int num = rand();
   cout << num << endl;
}
