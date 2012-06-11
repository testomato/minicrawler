#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

enum HtmlElement {
	H1, H2,	H3, H4,	H5, H6,
	UL, OL,
	PRE,
	P, DL, DIV, NOSCRIPT,
	BLOCKQUOTE, FORM, HR, TABLE, FIELDSET, ADDRESS,
	TD, TH,
	TR,
	IMG,
	SCRIPT, OPTION, STYLE,
	OTHER,
};

enum {
	ELEMS_NEWLINE = 1<<H1 | 1<<H2 |	1<<H3 | 1<<H4 |	1<<H5 | 1 << H6 | 1<<UL | 1<< OL | 1<< PRE | 1<<P | 1<< DL | 1 << DIV | 1 << NOSCRIPT | 1 <<  BLOCKQUOTE | 1 << FORM | 1 << HR | 1 << TABLE | 1 << FIELDSET | 1 << ADDRESS | 1<<TR,
	ELEMS_TAB = 1 << TD | 1 << TH,
	ELEMS_SPACE = 1<<IMG,
	ELEMS_SKIP_CONTENT = 1<<SCRIPT | 1<<OPTION | 1<<STYLE,
};

static const char *elems_names[] = {
	[H1] = "H1",
	[H2] = "H2",
	[H3] = "H3",
	[H4] = "H4",
	[H5] = "H5",
	[H6] = "H6",
	[UL] = "UL",
	[OL] = "OL",
	[PRE] = "PRE",
	[P] = "P",
	[DL] = "DL",
	[DIV] = "DIV",
	[NOSCRIPT] = "NOSCRIPT",
	[BLOCKQUOTE] = "BLOCKQUOTE",
	[FORM] = "FORM",
	[HR] = "HR",
	[TABLE] = "TABLE",
	[FIELDSET] = "FIELDSET",
	[ADDRESS] = "ADDRESS",
	[TD] = "TD",
	[TH] = "TH",
	[TR] = "TR",
	[IMG] = "IMG",
	[SCRIPT] = "SCRIPT",
	[OPTION] = "OPTION",
	[STYLE] = "STYLE",
	[OTHER] = NULL,
};

static char test_elems_number[OTHER < 32 ? 0 : -1];
static char test_elems_names[sizeof(elems_names) == (OTHER + 1)*sizeof(*elems_names) ? 0 : -1];

struct ElemDesc {
  unsigned id;
  unsigned begin : 1;
  unsigned end : 1;
};

static unsigned elem_name_to_id(const char *name)
{
	for (unsigned i = 0; i < sizeof(elems_names)/sizeof(*elems_names); ++i) {
		if (elems_names[i] && !strcasecmp(name, elems_names[i]))
			return i;
	}
	return OTHER;
}

static int crawler_is_space(const int c)
{
	return c == '\n' || c == '\r' || c == ' ' || c == '\t';
}

static char *consume_spaces(char *s, const char *end)
{
	for (; s < end && crawler_is_space(*s); ++s);
	return s;
}

static char *consume_nonspaces(char *s, const char *end)
{
	for (; s < end && !crawler_is_space(*s); ++s);
	return s;
}

static int crawler_is_tag_name(const int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

static char *consume_elem_name(char *s, const char *end)
{
	for (; s < end && crawler_is_tag_name(*s); ++s);
	return s;
}

static char *consume_until_c(char *s, const char *end, const char c)
{
	int backslash = 0;
	for (; s < end; ++s) {
		if (*s == c && !backslash)
			return ++s;
		backslash = *s == '\\' && !backslash;
	}
	return s;
}

static char *consume_elem(char *s, const char *end, struct ElemDesc *desc)
{
	if (s >= end)
		return s;
	if (*s != '<')
		return s;
	if ((s = consume_spaces(&s[1], end)) >= end)
		return s;
	*desc = (struct ElemDesc){};
	if (*s == '/') {
		desc->end = 1;
		if ((s = consume_spaces(&s[1], end)) >= end)
			return s;
	}
	else {
		desc->begin = 1;
	}
	const char *name = s;
        if ((s = consume_elem_name(&s[1], end)) >= end)
		return s;
	const int name_end_c = *s;
	*s = 0;
	desc->id = elem_name_to_id(name);
	*s = name_end_c;
	int previous_slash = 0;
	while ((s = consume_spaces(s, end)) < end) {
		if (*s == '>') {
			if (previous_slash)
				desc->end = 1;
			return ++s;
		}

		previous_slash = (*s == '/');

		if (*s == '"' || *s == '\'')  // FIXME: Can be backslash before this?
			s = consume_until_c(&s[1], end, *s);
		else
			++s;
	}
	return s;
}

static char *test_comment_start(char *s, const char *end)
{
	static const char comment_start[] = "<!--";
	unsigned i = 0;
	for (; i < sizeof(comment_start) - 1 && &s[i] < end && s[i] == comment_start[i]; ++i);
	return i == sizeof(comment_start) - 1 ? &s[sizeof(comment_start) - 1] : NULL;
}

static char *consume_comment(char *s, const char *end)
{
	static const char comment_end[] = "-->";
	for (; s < end; ++s) {
		if (*s == *comment_end) {
			unsigned i = 1;
			for (; i < sizeof(comment_end) - 1 && &s[i] < end && s[i] == comment_end[i]; ++i);
			if (i == sizeof(comment_end) - 1)
				return &s[sizeof(comment_end) - 1];
		}
	}
	return s;
}

static char *test_cdata_start(char *s, const char *end)
{
	static const char cdata_start[] = "<!CDATA[";
	unsigned i = 0;
	for (; i < sizeof(cdata_start) - 1 && &s[i] < end && s[i] == cdata_start[i]; ++i);
	return i == sizeof(cdata_start) - 1 ? &s[sizeof(cdata_start) - 1] : NULL;
}

static char *consume_cdata(char *s, const char *end, void (*f)(const int c))
{
	static const char cdata_end[] = "]]>";
	for (; s < end; ++s) {
		const int c = *s;
		if (c == '\n' || c == '\t') {
			f(' ');
		}
		else if (c == '\r')
			;
		else if (c == cdata_end[0]) {
			unsigned i = 1;
			for (; i < sizeof(cdata_end) - 1 && &s[i] < end && s[i] == cdata_end[i]; ++i);
			if (i == sizeof(cdata_end) - 1) {
				return &s[sizeof(cdata_end) - 1];
			}
			else {
				f(c);
			}
		}
		else {
			f(c);
		}
	}
	return s;
}

enum {
	CH_SPACE = 0,
	CH_SPACE_KILLER,
	CH_OTHER,
};

static struct {
	unsigned replace, skip;
} ch[] = {
	[CH_SPACE] = { 0, 1<<CH_SPACE | 1<<CH_SPACE_KILLER },
	[CH_SPACE_KILLER] = { 1<<CH_SPACE, 0 },
	[CH_OTHER] = { 0, 0 },
};

/** převede html na text
 * @param s vstupní řetězec (html); tamtéž se uloží i výstup (pozor, nemusí být ukončen nulou)
 * @param len velikost vstupního řetězce
 * @return velikost výstupního řetězce (textu)
 */
int converthtml2text(char *s, int len)
{
	// tady je Hagridovo :)

	unsigned hints = 0U;
	const char *end = &s[len];
	char *p_src = s, *p_dst = s;

	int ending = CH_SPACE_KILLER;
	void put_char(const int c)
	{
		if (hints & ELEMS_SKIP_CONTENT)
			return;
		const int act = c == ' ' ? CH_SPACE : c == '\n' || c == '\r' ? CH_SPACE_KILLER : CH_OTHER;
		if (1<<ending & ch[act].skip)
			;
		else if (1<<ending & ch[act].replace) {
			p_dst[-1] = c;
			ending = act;
		}
		else {
			*p_dst++ = c;
			ending = act;
		}
	}

	while (p_src < end) {
		assert(p_dst <= p_src);
		switch (*p_src) {
			case '\r':
				++p_src;
				break;
			case '\n':
			case '\t':
				put_char(' ');
				++p_src;
				break;
			case '&':;
				int code = 0;
				char dst[8];
				char *dst_end = NULL;
				char *p_src_new = consume_entity(p_src, end, &code);
				if (code && (dst_end = put_code(dst, sizeof(dst), code))) {
					for (char *p = dst; p < dst_end; ++p)
						put_char(*p);
					p_src = p_src_new;
				}
				else {
					put_char('&');
					++p_src;
				}
				break;
			case '<':;
				char *test_s;
				if ( (test_s = test_comment_start(p_src, end)) ) {
					p_src = consume_comment(test_s, end);
				}
				else if ( (test_s = test_cdata_start(p_src, end)) ) {
					p_src = consume_cdata(test_s, end, put_char);
				}
				else {
					struct ElemDesc elem_desc;
					p_src = consume_elem(p_src, end, &elem_desc);
					if (elem_desc.begin) {
						if (1<<elem_desc.id & ELEMS_NEWLINE)
							put_char('\n');
						if (1<<elem_desc.id & ELEMS_TAB)
							put_char('\t');
						if (1<<elem_desc.id & ELEMS_SPACE)
							put_char(' ');
					}
					if (elem_desc.begin != elem_desc.end)
						hints = elem_desc.begin ? hints | 1<<elem_desc.id : hints & ~(1<<elem_desc.id);
				}
				break;
			default:
				put_char(*p_src);
				++p_src;
		}
	}
	return p_dst - s;
}

struct tag_desc
{
	char *name;
	unsigned name_len;
	char *charset;
	unsigned charset_len;
	char *encoding;
	unsigned encoding_len;
	char *http_equiv;
	unsigned http_equiv_len;
	char *content;
	unsigned content_len;
};

struct tag_desc_pointer
{
	char **p;
	unsigned *l;
};

static int str_equiv_right(const char *left, const char *right, const size_t right_len)
{
	const char *pl = left, *pr = right;
	while (*pl && pr < &right[right_len]) {
		if (*pl++ != *pr++)
			return 0;
	}
	return !*pl;
}

static int str_equiv_right_nocase(const char *left, const char *right, const size_t right_len)
{
	const char *pl = left, *pr = right;
	for (; *pl && pr < &right[right_len]; ++pl, ++pr) {
		if (*pl >= 'A' && *pl <= 'Z') {
			if (*pl != (*pr & ~0x20))
				return 0;
		}
		else if (*pl >= 'a' && *pl <= 'z') {
			if (*pl != (*pr | 0x20))
				return 0;
		}
		else if (*pl != *pr) {
			return 0;
		}
	}
	return !*pl;
}

static void get_tag_desc_pointer(const char *name, const unsigned name_len, struct tag_desc *tag, struct tag_desc_pointer *pointer)
{
	if (str_equiv_right("charset", name, name_len)) {
		*pointer = (struct tag_desc_pointer) { .p = &tag->charset, .l = &tag->charset_len, };
	}
	else if (str_equiv_right("encoding", name, name_len)) {
		*pointer = (struct tag_desc_pointer) { .p = &tag->encoding, .l = &tag->encoding_len, };
	}
	else if (str_equiv_right("http-equiv", name, name_len)) {
		*pointer = (struct tag_desc_pointer) { .p = &tag->http_equiv, .l = &tag->http_equiv_len, };
	}
	else if (str_equiv_right("content", name, name_len)) {
		*pointer = (struct tag_desc_pointer) { .p = &tag->content, .l = &tag->content_len, };
	}
	else {
		*pointer = (struct tag_desc_pointer) {};
	}
}

static char *find_c(char *s, const char *end, const int c)
{
	for (; s < end && *s != c; ++s);
	return s;
}

static char *next_tag(char *s, const char *end, struct tag_desc *tag)
{
	*tag = (struct tag_desc) {};
	if ( (s = find_c(s, end, '<')) >= end)
		return s;
	if ( (tag->name = ++s) >= end || ++s >= end) // tag name is at least one char length, ! or ? can be the first char here
		return s;
	if ( (s = consume_elem_name(s, end)) >= end)
		return s;
	tag->name_len = s - tag->name;
	for (;;) {
		if ( (s = consume_spaces(s, end)) >= end)
			return s;
		if (*s == '/') {
			if (++s >= end)
				return s;
		}
		if (*s == '>') {
			return ++s;
		}
		char *param_name = s;
		if ( (s = consume_elem_name(&s[1], end)) >= end) // a bit of trick here, if senseless char at s[0], then it is supposed as attr name of length one
			return s;
		char *param_name_end = s;
		if ( (s = consume_spaces(s, end)) >= end)
			return s;
		if (*s == '=') {
			char *param_value = NULL;
			char *param_value_end = NULL;
			if ( (s = consume_spaces(&s[1], end)) >= end)
				return s;
			if (*s == '"' || *s == '\'') {
				param_value = &s[1];
				if ( (s = consume_until_c(&s[1], end, *s)) >= end)
					return s;
				param_value_end = &s[-1];
			}
			else {
				param_value = s;
				if ( (s = consume_elem_name(s, end)) >= end)
					return s;
				param_value_end = s;
			}
			struct tag_desc_pointer pointer;
			get_tag_desc_pointer(param_name, param_name_end - param_name, tag, &pointer);
			if (pointer.p) {
				*pointer.p = param_value;
				*pointer.l = param_value_end - param_value;
			}
		}
	}
	assert(0);
	return s;
}

char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len)
{
	const char *end = &s[len];
	while (s < end) {
		struct tag_desc tag;
		s = next_tag(s, end, &tag);
		if (str_equiv_right("?xml", tag.name, tag.name_len)) {
			if (tag.encoding) {
				*charset_len = tag.encoding_len;
				return tag.encoding;
			}
		}
		else if (str_equiv_right("meta", tag.name, tag.name_len)) {
			if (tag.encoding) {
				*charset_len = tag.encoding_len;
				return tag.encoding;
			}
			else if (tag.http_equiv && str_equiv_right_nocase("Content-Type", tag.http_equiv, tag.http_equiv_len) && tag.content) {
				const int c = tag.content[tag.content_len];
				tag.content[tag.content_len] = 0;
				const char charset[] = "charset=";
				char *encoding = strstr(tag.content, charset);
				tag.content[tag.content_len] = c;
				if (encoding) {
					encoding = &encoding[sizeof(charset) - 1];
					*charset_len = &tag.content[tag.content_len] - encoding;
					return encoding;
				}
			}
		}
	}
	return NULL;
}
