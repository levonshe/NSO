#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main()
{

   int i;
   char *p =malloc(1024*8*4);
   printf ( "main()=%p, malloced address = %p\n", main, p);

   p[1024*8+8000]='c';
   
return 1;
   for (i = 1; i < 1000; i++){
        p[1024*8+8000]='c';
   	sleep (1);
   }
return 1;
}
