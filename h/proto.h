

extern struct surl url[];
extern struct ssettings settings;

int gettimeint();
void go(void);
int converthtml2text(char *s, int len);
void conv_charset(struct surl *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);
