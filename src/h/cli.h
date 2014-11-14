#include "minicrawler.h"

void printusage();

void initurls(int argc, char *argv[], struct surl **urls, int *urllen, struct ssettings *settings);

void output(struct surl *u);
