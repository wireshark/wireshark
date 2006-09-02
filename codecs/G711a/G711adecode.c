#include <glib.h>
#include "G711adecode.h"
#include "G711atable.h"

int
decodeG711a(void *input, int inputSizeBytes, void *output, int *outputSizeBytes)
{
  guint8 *dataIn = (guint8 *)input;
  gint16 *dataOut = (gint16 *)output;
  int i;

  for (i=0; i<inputSizeBytes; i++)
  {
    dataOut[i] = alaw_exp_table[dataIn[i]];
  }
  *outputSizeBytes = inputSizeBytes * 2;
  return 0;
}

