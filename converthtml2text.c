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
	IMG,
	OTHER,
};

enum {
	ELEMS_NEWLINE = 1<<H1 | 1<<H2 |	1<<H3 | 1<<H4 |	1<<H5 | 1 << H6 | 1<<UL | 1<< OL | 1<< PRE | 1<<P | 1<< DL | 1 << DIV | 1 << NOSCRIPT | 1 <<  BLOCKQUOTE | 1 << FORM | 1 << HR | 1 << TABLE | 1 << FIELDSET | 1 << ADDRESS,
	ELEMS_TAB = 1 << TD | 1 << TH,
	ELEMS_SPACE = 1<<IMG
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
	[IMG] = "IMG",
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

/** převede html na text
 * @param s vstupní řetězec (html); tamtéž se uloží i výstup (pozor, nemusí být ukončen nulou)
 * @param len velikost vstupního řetězce
 * @return velikost výstupního řetězce (textu)
 */
int converthtml2text(char *s, int len)
{
	// tady je Hagridovo :)

	const char *end = &s[len];
	char *p_src = s, *p_dst = s;
	while (p_src < end) {
		assert(p_dst <= p_src);
		switch (*p_src) {
			case '\r':
				++p_src;
				break;
			case '\n':
			case '\t':
				*p_dst++ = ' ';
				++p_src;
				break;
			case '<':;
				struct ElemDesc elem_desc;
				p_src = consume_elem(p_src, end, &elem_desc);
				if (elem_desc.begin) {
					if (1<<elem_desc.id & ELEMS_NEWLINE)
						*p_dst++ = '\n';
					if (1<<elem_desc.id & ELEMS_TAB)
						*p_dst++ = '\t';
					if (1<<elem_desc.id & ELEMS_SPACE)
						*p_dst++ = ' ';
				}
				break;
			default:
				*p_dst++ = *p_src++;
		}
	}
	return p_dst - s;
}
