#include "struct.h"

void init_settings(struct ssettings *settings);

void init_url(struct surl *u, const char *url, const int index, char *post, struct cookie *cookies, const int cookiecnt);

void go(struct surl *url, const struct ssettings *settings);
