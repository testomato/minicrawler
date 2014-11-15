#include "minicrawler.h"

void printusage();

void initurls(int argc, char *argv[], mcrawler_url **urls, int *urllen, mcrawler_settings *settings);

void output(mcrawler_url *u);
