#include "shellPrograms.h"

/*  A program that prints how many summoned daemons are currently alive */
int shellCheckDaemon_code()
{

   /* TASK 8 */
   //Create a command that trawl through output of ps -efj and contains "summond"
   char *command = malloc(sizeof(char) * 256);
   sprintf(command, "ps -efj | grep summond  | grep -v tty > output.txt");

   // TODO: Execute the command using system(command) and check its return value
   int ans = system(command);

   if (ans == -1) {
      perror("Error executing command");
      return 1;
   }

   free(command);

   int live_daemons = 0;
   // TODO: Analyse the file output.txt, wherever you set it to be. You can reuse your code for countline program
   // 1. Open the file
   // 2. Fetch line by line using getline()
   // 3. Increase the daemon count whenever we encounter a line
   // 4. Close the file
   // 5. print your result

    char* buffer = malloc(sizeof(int) * 32);
    size_t size = sizeof(buffer);
    FILE *file = fopen("./output.txt", "r");

    if (buffer == NULL) {
        printf(" Buffer is null\n");
        return 1;

    } else if ( file == NULL) {
        printf("File not found.");
        return 1;
    }

    while(getline(&buffer, &size, file) > -1) {
      printf(buffer);
      live_daemons++;
    }   

    fclose(file);
    free(buffer);

   if (live_daemons == 0)
      printf("No daemon is alive right now\n");
   else
   {
      printf("There are in total of %d live daemons \n", live_daemons);
   }


   // TODO: close any file pointers and free any statically allocated memory 

   return 1;
}

int main(int argc, char **args)
{
   return shellCheckDaemon_code();
}