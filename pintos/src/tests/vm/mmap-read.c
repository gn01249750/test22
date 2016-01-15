/* Uses a memory mapping to read a file. */

#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  char *actual = (char *) 0x10000000;
  int handle;
  int a =5;
  mapid_t map;
  size_t i;
  // printf(" before memcmp \n");
  CHECK ((handle = open ("sample.txt")) > 1, "open \"sample.txt\"");
  //printf("check 1 \n");
  //printf("mapid: %d\n",a );
  map = mmap (handle, actual);
  //printf("mapid: %d\n",a );
  CHECK ((map = mmap (handle, actual)) != MAP_FAILED, "mmap \"sample.txt\"");

  //printf(" before memcmp after check \n");
  /* Check that data is correct. */
  if (memcmp (actual, sample, strlen (sample)))
    fail ("read of mmap'd file reported bad data");
  //printf("memcpm passed \n");

  /* Verify that data is followed by zeros. */
  for (i = strlen (sample); i < 4096; i++)
    if (actual[i] != 0)
      fail ("byte %zu of mmap'd region has value %02hhx (should be 0)",
            i, actual[i]);

  munmap (map);
  close (handle);
}
