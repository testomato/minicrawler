#include "../h/config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unicode/uidna.h>

#include "minicrawler-url.h"
#include "alloc.h"

#define debugf(...)   {fprintf(stderr, __VA_ARGS__);}

typedef enum {
	SCHEME_START,
	SCHEME,
	NO_SCHEME,
	SPECIAL_RELATIVE_OR_AUTHORITY,
	PATH_OR_AUTHORITY,
	RELATIVE,
	RELATIVE_SLASH,
	SPECIAL_AUTHORITY_SLASHES,
	SPECIAL_AUTHORITY_IGNORE_SLASHES,
	AUTHORITY,
	HOST,
	HOSTNAME,
	PORT,
	FILE_STATE,
	FILE_SLASH,
	FILE_HOST,
	PATH_START,
	PATH,
	CANNOT_BE_A_BASE_URL_PATH,
	QUERY,
	FRAGMENT
} state;

static inline char *strdupnul(const char *s) {
	return s ? strdup(s) : NULL;
}

static inline mcrawler_url_host *dup_host(mcrawler_url_host *host) {
	if (!host) {
		return NULL;
	}

	mcrawler_url_host *new = (mcrawler_url_host *)malloc(sizeof(mcrawler_url_host));
	memcpy(new, host, sizeof(mcrawler_url_host));
	new->domain = strdupnul(host->domain);
	return new;
}

static void trim_controls_and_space(char *str) {
	size_t len = strlen(str);
	char *p = str;
	while (len > 0 && str[len-1]  > 0 && str[len-1] <= ' ') str[--len] = '\0';
	while (*p > 0 && *p <= ' ') p++;
	if (str != p) {
		memmove(str, p, len+1 - (p-str));
	}
}

static inline int is_ascii_alpha(unsigned char c) {
	return (0x41 <= c && c <= 0x5A) || (0x61 <= c && c <= 0x7A);
}

static inline int is_ascii_digit(unsigned char c) {
	return 0x30 <= c && c <= 0x39;
}

static inline int is_ascii_hexdigit(unsigned char c) {
	return is_ascii_digit(c) || (0x41 <= c && c <= 0x46) || (0x61 <= c && c <= 0x66);
}

static inline int is_windows_drive_letter(char *s) {
	return is_ascii_alpha(s[0]) && (s[1] == ':' || s[1] == '|');
}

static inline int is_normalized_windows_drive_letter(char *s) {
	return is_ascii_alpha(s[0]) && s[1] == ':' && s[3] == 0;
}

static inline char tolowercase(unsigned char c) {
	return c >= 0x41 && c <= 0x5A ? c + (0x61-0x41) : c;
}

static inline int is_special(mcrawler_url_url *url) {
	if (!strcmp("http", url->scheme)) return 80;
	if (!strcmp("https", url->scheme)) return 443;
	if (!strcmp("ftp", url->scheme)) return 21;
	if (!strcmp("file", url->scheme)) return -1;
	if (!strcmp("gopher", url->scheme)) return 70;
	if (!strcmp("ws", url->scheme)) return 80;
	if (!strcmp("wss", url->scheme)) return 443;
	return 0;
}

static inline void pop_path(mcrawler_url_url *url) {
	// if url’s scheme is not "file" or url’s path does not contain a single string that is a normalized Windows drive letter, remove url’s path’s last string, if any.
	if (strcmp(url->scheme, "file") || !(url->path_len == 1 && is_normalized_windows_drive_letter(url->path[0]))) {
		do_pop_path(url);
	}
}


static inline int is_simple_encode_set(unsigned char c) {
	return c < 0x20 || c >= 0x7F;
}

static inline int is_default_encode_set(unsigned char c) {
	return is_simple_encode_set(c) || c == 0x20 || c == '"' || c == '#' || c == '<' || c == '>' || c == '?' || c == '`' || c == '{' || c == '}';
}

static inline int is_userinfo_encode_set(unsigned char c) {
	return is_default_encode_set(c) || c == '/' || c == ':' || c == ';' || c == '=' || c == '@' || c == '[' || c == ']' || c == '\\' || c == '^' || c == '|';
}

static inline void percent_encode(char *buf, unsigned char c) {
	sprintf(buf, "%%%2.2X", c);
}

static void percent_decode(char *output, int *length, const char *input) {
	// Let output be an empty byte sequence.
	int outp = 0;
	// For each byte byte in input, run these steps:
	const char *p = input;
	char c;
	while ((c = *p++)) {
		// If byte is not `%`, append byte to output.
		if (c != '%') {
			output[outp++] = c;
		// Otherwise, if byte is `%` and the next two bytes after byte in input are not in the ranges 0x30 to 0x39, 0x41 to 0x46, and 0x61 to 0x66, append byte to output.
		} else if (
			!((0x30 <= p[0] && p[0] <= 0x39) || (0x41 <= p[0] && p[0] <= 0x46) || (0x61 <= p[0] && p[0] <= 0x66)) &&
			!(p[0] == 0 || (0x30 <= p[1] && p[1] <= 0x39) || (0x41 <= p[1] && p[1] <= 0x46) || (0x61 <= p[1] && p[1] <= 0x66))
		) {
			output[outp++] = c;
		// Otherwise, run these substeps:
		} else {
			// Let bytePoint be the two bytes after byte in input, decoded, and then interpreted as hexadecimal number.
			char bytes[3] = {0, 0, 0};
			strncpy(bytes, p, 2);
			int r = sscanf(bytes, "%X", (unsigned int *)(output + outp));
			// Append a byte whose value is bytePoint to output.
			if (r) {
				outp++;
			}
			// Skip the next two bytes in input.
			p += 2;
		}
	}
	// Return output.	
	output[outp] = 0;
	*length = outp;
}

static int domain_to_ascii(char *result, int length, char *domain) {
	// Let result be the result of running Unicode ToASCII with domain_name set to domain, UseSTD3ASCIIRules set to false, processing_option set to Transitional_Processing, and VerifyDnsLength set to false.
	if (domain[0] == 0) {
		result[0] = 0;
		return MCRAWLER_URL_SUCCESS;
	}

	UErrorCode error = 0;
	UIDNA *idna = uidna_openUTS46(UIDNA_DEFAULT, &error);
	if (U_FAILURE(error)) {
		debugf("Error %s (%d) for %s\n", u_errorName(error), error, domain);
		return MCRAWLER_URL_FAILURE;
	}
	error = 0;
	UIDNAInfo info = UIDNA_INFO_INITIALIZER;
	uidna_nameToASCII_UTF8(idna, domain, -1, result, length, &info, &error);
	uidna_close(idna);
	if (U_SUCCESS(error) && error != U_STRING_NOT_TERMINATED_WARNING && info.errors == 0) {
		return MCRAWLER_URL_SUCCESS;
	}
	if (error) {
		debugf("Error %s (%d) for %s\n", u_errorName(error), error, domain);
	}
	return MCRAWLER_URL_FAILURE;
}

static inline int is_single_dot(char *s) {
	return !strcmp(s, ".") || !strcasecmp(s, "%2e");
}

static inline int is_double_dot(char *s) {
	return !strcmp(s, "..") || !strcasecmp(s, ".%2e") || !strcasecmp(s, "%2e.") || !strcasecmp(s, "%2e%2e");
}


int mcrawler_url_parse_ipv6(mcrawler_url_host *host, const char *input) {
	// Let address be a new IPv6 address with its 16-bit pieces initialized to 0.
	uint16_t address[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	// Let piece pointer be a pointer into address’s 16-bit pieces, initially zero (pointing to the first 16-bit piece), and let piece be the 16-bit piece it points to.
	uint16_t *p_piece = address;
	// Let compress pointer be another pointer into address’s 16-bit pieces, initially null and pointing to nothing.
	uint16_t *p_compress = NULL;
	// Let pointer be a pointer into input, initially zero (pointing to the first code point).
	const char *p = input;
	char c;
	// If c is ":", run these substeps:
	if (*p == ':') {
		// If remaining does not start with ":", syntax violation, return failure.
		if (p[1] != ':') {
			debugf("IPv6 syntax violation (5.1) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// Increase pointer by two.
		p += 2;
		// Increase piece pointer by one and then set compress pointer to piece pointer.
		p_piece++; p_compress = p_piece;
	}
	// Main: While c is not the EOF code point, run these substeps:
Main:
	while ((c = *p)) {
		// If piece pointer is eight, syntax violation, return failure.
		if (p_piece - address == 8) {
			debugf("IPv6 syntax violation (6.1) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// If c is ":", run these inner substeps:
		if (c == ':') {
			// If compress pointer is non-null, syntax violation, return failure.
			if (p_compress) {
				debugf("IPv6 syntax violation (6.2.1) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
			// Increase pointer and piece pointer by one, set compress pointer to piece pointer, and then jump to Main.
			c = *++p; p_piece++; p_compress = p_piece;
			goto Main;
		}
		// Let value and length be 0.
		uint16_t value = 0, length = 0;
		// While length is less than 4 and c is an ASCII hex digit, set value to value × 0x10 + c interpreted as hexadecimal number, and increase pointer and length by one.
		while (length < 4 && is_ascii_hexdigit(c)) {
			char temp[2] = {c, 0};
			value = value * 0x10 + strtol(temp, NULL, 16);
			c = *++p; length++;
		}
		// Switching on c:
		switch (c) {
		case '.':
			// If length is 0, syntax violation, return failure.
			if (length == 0) {
				debugf("IPv6 syntax violation (6.5) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
			// Decrease pointer by length.
			p -= length;
			// Jump to IPv4.
			goto IPv4;
		case ':':
			// Increase pointer by one.
			c = *++p;
			// If c is the EOF code point, syntax violation, return failure.
			if (*p == 0) {
				debugf("IPv6 syntax violation (6.5) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
			break;
		case 0:
			break;
		// Anything but the EOF code point
		default:
			// Syntax violation, return failure.
			debugf("IPv6 syntax violation (6.5) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// Set piece to value.
		*p_piece = value;
		// Increase piece pointer by one.
		p_piece++;
	}
	// If c is the EOF code point, jump to Finale.
	if (c == 0) {
		goto Finale;
	}

	// IPv4: If piece pointer is greater than six, syntax violation, return failure.
IPv4:
	if (p_piece - address > 6) {
		debugf("IPv6 syntax violation (8.1) at %s\n", p);
		return MCRAWLER_URL_FAILURE;
	}
	// Let dots seen be 0.
	int dots_seen = 0;
	// While c is not the EOF code point, run these substeps:
	while ((c = *p)) {
		// Let value be null.
		int value_null = 1;
		uint16_t value;
		// If c is not an ASCII digit, syntax violation, return failure.
		if (!is_ascii_digit(c)) {
			debugf("IPv6 syntax violation (10.2) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// While c is an ASCII digit, run these subsubsteps:
		while (is_ascii_digit(c = *p)) {
			// Let number be c interpreted as decimal number.
			uint16_t number = c - 0x30;
			// If value is null, set value to number.
			if (value_null) {
				value = number;
				value_null = 0;
			// Otherwise, if value is 0, syntax violation, return failure.
			} else if (value == 0) {
				debugf("IPv6 syntax violation (10.3.2) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			// Otherwise, set value to value × 10 + number.
			} else {
				value = value * 10 + number;
			}
			// Increase pointer by one.
			c = *++p;
			// If value is greater than 255, syntax violation, return failure.
			if (value > 255) {
				debugf("IPv6 syntax violation (10.3.4) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
		}
		// If dots seen is less than 3 and c is not a ".", syntax violation, return failure.
		if (dots_seen < 3 && c != '.') {
			debugf("IPv6 syntax violation (10.4) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// Set piece to piece × 0x100 + value.
		*p_piece = *p_piece * 0x100 + value;
		// If dots seen is 1 or 3, increase piece pointer by one.
		if (dots_seen == 1 || dots_seen == 3) {
			p_piece++;
		}
		// If c is not the EOF code point, increase pointer by one.
		if (c != 0) {
			c = *++p;
		}
		// If dots seen is 3 and c is not the EOF code point, syntax violation, return failure.
		if (dots_seen == 3 && c != 0) {
			debugf("IPv6 syntax violation (10.8) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
		// Increase dots seen by one.
		dots_seen++;
	}
	// Finale: If compress pointer is non-null, run these substeps:
Finale:
	if (p_compress) {
		// Let swaps be piece pointer − compress pointer.
		int swaps = p_piece - p_compress;
		// Set piece pointer to seven.
		p_piece = address + 7;
		// While piece pointer is not zero and swaps is greater than zero, swap piece with the piece at pointer compress pointer + swaps − 1, and then decrease both piece pointer and swaps by one.
		while (p_piece > address && swaps > 0) {
			uint16_t tmp = *p_piece;
			*p_piece = *(p_compress + swaps - 1);
			*(p_compress + swaps - 1) = tmp;
			p_piece--; swaps--;
		}
	// Otherwise, if compress pointer is null and piece pointer is not eight, syntax violation, return failure.
	} else if (p_piece - address != 8) {
		debugf("IPv6 syntax violation (12) at %s\n", p);
		return MCRAWLER_URL_FAILURE;
	}
	// Return address.
	host->type = MCRAWLER_URL_HOST_IPV6;
	for (int i = 0; i < 8; i++) {
		address[i] = htons(address[i]);
	}
	memcpy(host->ipv6, address, 16);
	char *ipv6str = mcrawler_url_serialize_ipv6(host);
	free(host->domain);
	host->domain = malloc(strlen(ipv6str) + 3);
	host->domain[0] = '[';
	strcpy(host->domain + 1, ipv6str);
	strcpy(host->domain + 1 + strlen(ipv6str), "]");
	return MCRAWLER_URL_SUCCESS;
}

static int parse_ipv4_number(uint32_t *number, char *input, int *syntaxViolationFlag) {
	// Let R be 10.
	int R = 10;
	char allowed[23] = "0123456789";

	// If input contains at least two code points and the first two code points are either "0x" or "0X", run these substeps:
	if (input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
		// Set syntaxViolationFlag.
		*syntaxViolationFlag = 1;
		// Remove the first two code points from input.
		input = input + 2;
		// Set R to 16.
		R = 16;
		strcpy(allowed, "0123456789abcdefABCDEF");
	}
	// If input is the empty string, return zero.
	if (input[0] == 0) {
		*number = 0;
		return MCRAWLER_URL_SUCCESS;
	}
	// Otherwise, if input contains at least two code points and the first code point is "0", run these substeps:
	if (R != 16 && input[0] == '0' && input[1]) {
		// Set syntaxViolationFlag.
		*syntaxViolationFlag = 1;
		// Remove the first code point from input.
		input = input + 1;
		// Set R to 8.
		R = 8;
		strcpy(allowed, "01234567");
	}
	// If input contains a code point that is not a radix-R digit, and return failure.
	if (strspn(input, allowed) < strlen(input)) {
		return MCRAWLER_URL_FAILURE;
	}
	// Return the mathematical integer value that is represented by input in radix-R notation, using ASCII hex digits for digits with values 0 through 15.
	long long int n = strtoll(input, NULL, R);
	if (n >= 1LL<<32) {
		return MCRAWLER_URL_FAILURE;
	}
	*number = (uint32_t)n;
	return MCRAWLER_URL_SUCCESS;
}

int mcrawler_url_parse_ipv4(mcrawler_url_host *host, const char *input) {
	// Let syntaxViolationFlag be unset.
	int syntaxViolationFlag = 0;
	// Let parts be input split on ".".
	int count = 1;
	char *parts[5] = {strdup(input), NULL, NULL, NULL, NULL};
	char c, *p = parts[count - 1];
	while ((c = *p++)) {
		if (c == '.') {
			if (++count <= 5) {
				parts[count - 1] = p;
			}
			*(p - 1) = 0;
		}
	}
	// If the last item in parts is the empty string, set syntaxViolationFlag and remove the last item from parts.
	if (count <= 5 && strlen(parts[count - 1]) == 0) {
		syntaxViolationFlag = 1;
		count--;
	}
	// If parts has more than four items, return input.
	if (count > 4 || count == 0) {
		free(parts[0]);
		return MCRAWLER_URL_SUCCESS;
	}
	// Let numbers be the empty list.
	uint32_t numbers[4];
	// For each part in parts:
	for (int i = 0; i < count; i++) {
		// If part is the empty string, return input.
		if (strlen(parts[i]) == 0) {
			// 0..0x300 is a domain, not an IPv4 address.
			free(parts[0]);
			return MCRAWLER_URL_SUCCESS;
		}
		// Let n be the result of parsing part using syntaxViolationFlag.
		// If n is failure, return input.
		// Append n to numbers.
		if (parse_ipv4_number(&numbers[i], parts[i], &syntaxViolationFlag) == MCRAWLER_URL_FAILURE) {
			free(parts[0]);
			return MCRAWLER_URL_SUCCESS;
		}
	}
	// If syntaxViolationFlag is set, syntax violation.
	// If any item in numbers is greater than 255, syntax violation.
	// If any but the last item in numbers is greater than 255, return failure.
	for (int i = 0; i < count - 1; i++) {
		if (numbers[i] > 255) {
			debugf("IPv4 syntax violation (8) at %s\n", parts[i]);
			free(parts[0]);
			return MCRAWLER_URL_FAILURE;
		}
	}
	// If the last item in numbers is greater than or equal to 256^(5 − the number of items in numbers), syntax violation, return failure.
	if (count > 0 && numbers[count - 1] >= 1LL<<(8*(5-count))) {
		// count == 0: number cannot be grater than 2^32
		debugf("IPv4 syntax violation (10) at %s\n", parts[count - 1]);
		free(parts[0]);
		return MCRAWLER_URL_FAILURE;
	}
	// Let ipv4 be the last item in numbers.
	uint32_t ipv4 = numbers[count - 1];
	// Remove the last item from numbers.
	count--;
	// Let counter be zero.
	// For each n in numbers:
	for (int i = 0; i < count; i++) {
		// Increment ipv4 by n × 256^(3 − counter).
		ipv4 += numbers[i] * 1<<(8*(3-i));
		// Increment counter by one.
	}
	// Return ipv4.
	host->type = MCRAWLER_URL_HOST_IPV4;
	ipv4 = htonl(ipv4);
	memcpy(host->ipv4, &ipv4, 4);
	free(host->domain);
	host->domain = mcrawler_url_serialize_ipv4(host);
	free(parts[0]);
	return MCRAWLER_URL_SUCCESS;
}

int mcrawler_url_parse_host(mcrawler_url_host *host, const char *input) {
	memset(host, 0, sizeof(mcrawler_url_host));

	if (!input) {
		return MCRAWLER_URL_FAILURE;
	}

	size_t len = strlen(input);
	// If input starts with "[", run these substeps:
	if (input[0] == '[') {
		// If input does not end with "]", syntax violation, return failure.
		if (input[len - 1] != ']') {
			debugf("Host syntax violation (1.1) for %s\n", input);
			return MCRAWLER_URL_FAILURE;
		}
		char *inp = strdup(input + 1);
		inp[len - 2] = 0;
		// Return the result of IPv6 parsing input with its leading "[" and trailing "]" removed.
		int r = mcrawler_url_parse_ipv6(host, inp);
		free(inp);
		return r;
	}
	// Let domain be the result of UTF-8 decode without BOM on the percent decoding of UTF-8 encode on input.
	char domain[len + 1];
	percent_decode(domain, (int *)&len, input);
	// U+0000 is not allowed in domain (see 5)
	if (strlen(domain) != len) {
		debugf("Host parsing failure (5) for %s\n", input);
		return MCRAWLER_URL_FAILURE;
	}
	// Let asciiDomain be the result of running domain to ASCII on domain.
	char asciiDomain[256]; // we will reject asciiDomain longer that 255 chars
	if (domain_to_ascii(asciiDomain, 256, domain) == MCRAWLER_URL_FAILURE) {
		// If asciiDomain is failure, return failure.
		debugf("Host parsing failure (4) for %s\n", input);
		return MCRAWLER_URL_FAILURE;
	}
	// If asciiDomain contains U+0000, U+0009, U+000A, U+000D, U+0020, "#", "%", "/", ":", "?", "@", "[", "\", or "]", syntax violation, return failure.
	char *q;
	if ((q = strpbrk(asciiDomain, "\x09\x0A\x09\x20#%/:?@[\\]"))) {
		debugf("Host syntax violation (5) for %s at %s\n", input, q);
		return MCRAWLER_URL_FAILURE;
	}
	// Let ipv4Host be the result of IPv4 parsing asciiDomain.
	// If ipv4Host is an IPv4 address or failure, return ipv4Host.
	if (mcrawler_url_parse_ipv4(host, asciiDomain) == MCRAWLER_URL_FAILURE) {
		return MCRAWLER_URL_FAILURE;
	}
	if (host->type == MCRAWLER_URL_HOST_IPV4) {
		return MCRAWLER_URL_SUCCESS;
	}

	// Return asciiDomain if the Unicode flag is unset, and the result of running domain to Unicode on asciiDomain otherwise.
	host->type = MCRAWLER_URL_HOST_DOMAIN;
	free(host->domain);
	host->domain = strdup(asciiDomain);
	return MCRAWLER_URL_SUCCESS;
}

int mcrawler_url_parse(mcrawler_url_url *url, const char *input_par, const mcrawler_url_url *base)
{
	if (!input_par) {
		return MCRAWLER_URL_FAILURE;
	}

	size_t len = strlen(input_par);
	char input[len + 1];
	strcpy(input, input_par);

	// Set url to a new URL.
	init_url(url);

	// Remove any leading and trailing C0 controls and space from input.
	trim_controls_and_space(input);

	char *p;

	// Remove all tab and newline from input.
	p = input;
	while (*p) {
		if (*p == '\t' || *p == '\n' || *p == '\r') {
			debugf("Syntax violation at %s\n", p);
			memmove(p, p+1, len-- - (p-input));
		} else {
			p++;
		}
	}

	// Let state be Scheme start state
	state state = SCHEME_START;

	// Let buffer be the empty string.
	char buf[3 * len + 1]; // 3x because percent encoding
	int bufp = 0;

	// Let the @ flag and the [] flag be unset.
	int flag_at = 0, flag_sq = 0;

	// Let pointer be a pointer to first code point in input.
	p = input;
	do {
		char c = *p;
		switch (state) {
			case SCHEME_START:
				// If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state.
				if (is_ascii_alpha(c)) {
					buf[bufp++] = tolowercase(c);
					state = SCHEME;
				// Otherwise, if state override is not given, set state to no scheme state, and decrease pointer by one.
				} else {
					state = NO_SCHEME;
					p--;
				}
				break;
			case SCHEME:
				// If c is an ASCII alphanumeric, "+", "-", or ".", append c, lowercased, to buffer.
				if (is_ascii_alpha(c) || c == '+' || c == '-' || c == '.') {
					buf[bufp++] = tolowercase(c);
				// Otherwise, if c is ":", run these substeps:
				} else if (c == ':') {
					// Set url’s scheme to buffer.
					buf[bufp] = 0;
					replace_scheme(url, buf);
					// Set buffer to the empty string.
					bufp = 0;
					// If url’s scheme is "file", run these subsubsteps:
					if (!strcmp("file", url->scheme)) {
						// If remaining does not start with "//", syntax violation.
						if (p[1] != '/' || p[2] != '/') {
							debugf("syntax violation (scheme 2.5.1) at %s\n", p);
						}
						// Set state to file state.
						state = FILE_STATE;
					// Otherwise, if url is special, base is non-null, and base’s scheme is equal to url’s scheme, set state to special relative or authority state.
					} else if (is_special(url)) {
						if (base && !strcmp(url->scheme, base->scheme)) {
							state = SPECIAL_RELATIVE_OR_AUTHORITY;
						// Otherwise, if url is special, set state to special authority slashes state.
						} else {
							state = SPECIAL_AUTHORITY_SLASHES;
						}
					// Otherwise, if remaining starts with an "/", set state to path or authority state, and increase pointer by one.
					} else if (p[1] == '/') {
						state = PATH_OR_AUTHORITY;
						p++;
					// Otherwise, set url’s non-relative flag, append an empty string to url’s path, and set state to non-relative path state.
					} else {
						url->cannot_be_a_base_url = 1;
						append_path(url, "");
						state = CANNOT_BE_A_BASE_URL_PATH;
					}
				// Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state, and start over (from the first code point in input).
				} else {
					bufp = 0;
					state = NO_SCHEME;
					p = input - 1;
				}
				break;
			case NO_SCHEME:
				// If base is null, or base’s non-relative flag is set and c is not "#", syntax violation, return failure.
				if (!base || (base->cannot_be_a_base_url && c != '#')) {
					debugf("Syntax violation (no scheme 1) at %s\n", p);
					return MCRAWLER_URL_FAILURE;
				// Otherwise, if base’s non-relative flag is set and c is "#", set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, set url’s non-relative flag, and set state to fragment state.
				} else if (base->cannot_be_a_base_url && c == '#') {
					replace_scheme(url, base->scheme);
					replace_path(url, (const char **)base->path);
					url->query = strdupnul(base->query);
					init_fragment(url);
					url->cannot_be_a_base_url = 1;
					state = FRAGMENT;
				// Otherwise, if base’s scheme is not "file", set state to relative state and decrease pointer by one.
				} else if (!base->scheme || strcmp(base->scheme, "file")) {
					state = RELATIVE;
					p--;
				// Otherwise, set state to file state and decrease pointer by one.
				} else {
					state = FILE_STATE;
					p--;
				}
				break;
			case SPECIAL_RELATIVE_OR_AUTHORITY:
				// If c is "/" and remaining starts with "/", set state to special authority ignore slashes state and increase pointer by one.
				if (c == '/' && p[1] == '/') {
					state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
					p++;
				// Otherwise, syntax violation, set state to relative state and decrease pointer by one.
				} else {
					debugf("Syntax violation (special relative or authority) at %s\n", p);
					state = RELATIVE;
					p--;
				}
				break;
			case PATH_OR_AUTHORITY:
				// If c is "/", set state to authority state.
				if (c == '/') {
					state = AUTHORITY;
				// Otherwise, set state to path state, and decrease pointer by one.
				} else {
					state = PATH;
					p--;
				}
				break;
			case RELATIVE:
				// Set url’s scheme to base’s scheme, and then, switching on c:
				replace_scheme(url, base->scheme);
				switch (c) {
					case 0:
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, and url’s query to base’s query.
						replace_username(url, base->username);
						url->password = strdupnul(base->password);
						url->host = dup_host(base->host);
						url->port = base->port;
						url->port_not_null = base->port_not_null;
						replace_path(url, (const char **)base->path);
						url->query = strdupnul(base->query);
						break;
					case '/':
						// Set state to relative slash state.
						state = RELATIVE_SLASH;
						break;
					case '?':
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, url’s query to the empty string, and state to query state.
						replace_username(url, base->username);
						url->password = strdupnul(base->password);
						url->host = dup_host(base->host);
						url->port = base->port;
						url->port_not_null = base->port_not_null;
						replace_path(url, (const char **)base->path);
						init_query(url);
						state = QUERY;
						break;
					case '#':
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, and state to fragment state.
						replace_username(url, base->username);
						url->password = strdupnul(base->password);
						url->host = dup_host(base->host);
						url->port = base->port;
						url->port_not_null = base->port_not_null;
						replace_path(url, (const char **)base->path);
						url->query = strdupnul(base->query);
						init_fragment(url);
						state = FRAGMENT;
						break;
					default:
						// If url is special and c is "\", syntax violation, set state to relative slash state.
						if (c == '\\' && is_special(url)) {
							debugf("Syntax violation (relative) at %s\n", p);
							state = RELATIVE_SLASH;
						} else {
							// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, and then remove url’s path’s last entry, if any.
							replace_username(url, base->username);
							url->password = strdupnul(base->password);
							url->host = dup_host(base->host);
							url->port = base->port;
							url->port_not_null = base->port_not_null;
							replace_path(url, (const char **)base->path);
							do_pop_path(url);
							// Set state to path state, and decrease pointer by one.
							state = PATH;
							p--;
						}
				}
				break;
			case RELATIVE_SLASH:
				// If either c is "/", or url is special and c is "\", run these substeps:
				if (c == '/' || (c == '\\' && is_special(url))) {
					// If c is "\", syntax violation.
					if (c == '\\') {
						debugf("Syntax violation (relative slash 1.1) at %s\n", p);
					}
					// Set state to special authority ignore slashes state.
					state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
				// Otherwise, set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, state to path state, and then, decrease pointer by one.
				} else {
					replace_username(url, base->username);
					url->password = strdupnul(base->password);
					url->host = dup_host(base->host);
					url->port = base->port;
					url->port_not_null = base->port_not_null;
					state = PATH;
					p--;
				}
				break;
			case SPECIAL_AUTHORITY_SLASHES:
				// If c is "/" and remaining starts with "/", set state to special authority ignore slashes state, and increase pointer by one.
				if (c == '/' && p[1] == '/') {
					state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
					p++;
				// Otherwise, syntax violation, set state to special authority ignore slashes state, and decrease pointer by one.
				} else {
					debugf("Syntax violation (special authority slashes) at %s\n", p);
					state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
					p--;
				}
				break;
			case SPECIAL_AUTHORITY_IGNORE_SLASHES:
				// If c is neither "/" nor "\", set state to authority state, and decrease pointer by one.
				if (c != '/' && c != '\\') {
					state = AUTHORITY;
					p--;
				} else {
					// Otherwise, syntax violation.
					debugf("Syntax violation (special authority ignore slashes) at %s\n", p);
				}
				break;
			case AUTHORITY:
				// If c is "@", run these substeps:
				if (c == '@') {
					// Syntax violation.
					debugf("Syntax violation (authority 1.1) at %s\n", p);
					// If the @ flag is set, prepend "%40" to buffer.
					if (flag_at) {
						memmove(buf + 3, buf, bufp + 1);
						strncpy(buf, "%40", 3);
						bufp += 3;
					}
					// Set the @ flag.
					flag_at = 1;
					// For each codePoint in buffer, run these substeps:
					int username_p = strlen(url->username);
					int password_p = url->password ? strlen(url->password) : 0;
					for (int i = 0; i < bufp; i++) {
						// If codePoint is ":" and url’s password is null, set url’s password to the empty string and run these substeps for the next code point.
						if (buf[i] == ':' && !url->password) {
							init_password(url);
							continue;
						}
						// Let encodedCodePoints be the result of running UTF-8 percent encode codePoint using the userinfo encode set.
						char encodedCodePoints[4] = {0, 0, 0, 0};
						if (is_userinfo_encode_set(buf[i])) {
							percent_encode(encodedCodePoints, buf[i]);
						} else {
							encodedCodePoints[0] = buf[i];
						}
						// If url’s password is non-null, append encodedCodePoints to url’s password.
						// Otherwise, append encodedCodePoints to url’s username.
						if (url->password) {
							append_password(url, &password_p, encodedCodePoints);
						} else {
							append_username(url, &username_p, encodedCodePoints);
						}
					}
					// Set buffer to the empty string.
					bufp = 0;

				// Otherwise, if one of the following is true
				} else if (
					// c is EOF code point, "/", "?", or "#"
					(c == 0 || c == '/' || c == '?' || c == '#') ||
					// url is special and c is "\"
					(c == '\\' && is_special(url))
				) {
					// then decrease pointer by the number of code points in buffer plus one, set buffer to the empty string, and set state to host state.
					p -= bufp + 1;
					bufp = 0;
					state = HOST;
				// Otherwise, append c to buffer.
				} else {
					buf[bufp++] = c;
				}
				break;
			case HOST:
			case HOSTNAME:
				// If c is ":" and the [] flag is unset, run these substeps:
				if (c == ':' && !flag_sq) {
					// If url is special and buffer is the empty string, return failure.
					if (bufp == 0 && is_special(url)) {
						return MCRAWLER_URL_FAILURE;
					}
					// Let host be the result of host parsing buffer.
					// If host is failure, return failure.
					buf[bufp] = 0;
					url->host = (mcrawler_url_host *)malloc(sizeof (mcrawler_url_host));
					if (mcrawler_url_parse_host(url->host, buf) == MCRAWLER_URL_FAILURE) {
						free(url->host);
						url->host = NULL;
						return MCRAWLER_URL_FAILURE;
					}
					// Set url’s host to host, buffer to the empty string, and state to port state.
					bufp = 0;
					state = PORT;
				// Otherwise, if one of the following is true
				} else if (
					// c is EOF code point, "/", "?", or "#"
					(c == 0 || c == '/' || c == '?' || c == '#') ||
					// url is special and c is "\"
					(c == '\\' && is_special(url))
				) {
					// then decrease pointer by one, and run these substeps:
					p--;
					// If url is special and buffer is the empty string, return failure.
					if (bufp == 0 && is_special(url)) {
						return MCRAWLER_URL_FAILURE;
					}
					// Let host be the result of host parsing buffer.
					// If host is failure, return failure.
					buf[bufp] = 0;
					url->host = (mcrawler_url_host *)malloc(sizeof (mcrawler_url_host));
					if (mcrawler_url_parse_host(url->host, buf) == MCRAWLER_URL_FAILURE) {
						free(url->host);
						url->host = NULL;
						return MCRAWLER_URL_FAILURE;
					}
					// Set url’s host to host, buffer to the empty string, and state to path start state.
					bufp = 0;
					state = PATH_START;
				// Otherwise, run these substeps:
				} else {
					// If c is "[", set the [] flag.
					if (c == '[') {
						flag_sq = 1;
					}
					// If c is "]", unset the [] flag.
					if (c == ']') {
						flag_sq = 0;
					}
					// Append c to buffer.
					buf[bufp++] = c;
				}
				break;
			case PORT:
				// If c is an ASCII digit, append c to buffer.
				if (is_ascii_digit(c)) {
					buf[bufp++] = c;
				// Otherwise, if one of the following is true
				} else if (
					// c is EOF code point, "/", "?", or "#"
					(c == 0 || c == '/' || c == '?' || c == '#') ||
					// url is special and c is "\"
					(c == '\\' && is_special(url))
				) {
					// If buffer is not the empty string, run these subsubsteps:
					if (bufp) {
						// Let port be the mathematical integer value that is represented by buffer in radix-10 using ASCII digits for digits with values 0 through 9.
						buf[bufp] = 0;
						long port = atol(buf);
						// If port is greater than 2^16 − 1, syntax violation, return failure.
						if (port > (1L<<16) - 1) {
							debugf("Syntax violation (port 2.1.2) at %s\n", p);
							return MCRAWLER_URL_FAILURE;
						}
						// Set url’s port to null, if port is url’s scheme’s default port, and to port otherwise.
						if (is_special(url) == port) {
							url->port_not_null = 0;
						} else {
							url->port_not_null = 1;
							url->port = port;
						}
						// Set buffer to the empty string.
						bufp = 0;
					}
					// Set state to path start state, and decrease pointer by one.
					state = PATH_START;
					p--;
				// Otherwise, syntax violation, return failure.
				} else {
					debugf("Syntax violation (port 3) at %s\n", p);
					return MCRAWLER_URL_FAILURE;
				}
				break;
			case FILE_STATE:
				// Set url’s scheme to "file", and then, switching on c:
				replace_scheme(url, "file");
				switch (c) {
					case 0:
						// If base is non-null and base’s scheme is "file", set url’s host to base’s host, url’s path to base’s path, and url’s query to base’s query.
						if (base && !strcmp(base->scheme, "file")) {
							url->host = dup_host(base->host);
							replace_path(url, (const char **)base->path);
							url->query = strdupnul(base->query);
						}
						break;
					case '\\':
						// If c is "\", syntax violation.
						debugf("Syntax violation (\\) at %s\n", p);
					case '/':
						// Set state to file slash state.
						state = FILE_SLASH;
						break;
					case '?':
						// If base is non-null and base’s scheme is "file", set url’s host to base’s host, url’s path to base’s path, url’s query to the empty string, and state to query state.
						if (base && !strcmp(base->scheme, "file")) {
							url->host = dup_host(base->host);
							replace_path(url, (const char **)base->path);
							init_query(url);
							state = QUERY;
						}
						break;
					case '#':
						// If base is non-null and base’s scheme is "file", set url’s host to base’s host, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, and state to fragment state.
						if (base && !strcmp(base->scheme, "file")) {
							url->host = dup_host(base->host);
							replace_path(url, (const char **)base->path);
							url->query = strdupnul(base->query);
							init_fragment(url);
							state = FRAGMENT;
						}
						break;
					default:
						// If base is non-null, base’s scheme is "file", and at least one of the following is true
						if (base && !strcmp(base->scheme, "file") && (
							// c and the first code point of remaining are not a Windows drive letter
							!is_windows_drive_letter(p) ||
							// remaining consists of one code point
							(p[1] != 0 && p[2] == 0) ||
							// remaining’s second code point is not "/", "\", "?", or "#"
							(p[2] != '/' && p[2] != '\\' && p[2] != '?' && p[2] != '#')
						)) {
							// then set url’s host to base’s host, url’s path to base’s path, and then pop url’s path.
							url->host = dup_host(base->host);
							replace_path(url, (const char **)base->path);
							pop_path(url);
							// This is a (platform-independent) Windows drive letter quirk.
						// Otherwise, if base is non-null and base’s scheme is "file", syntax violation.
						} else if (base && !strcmp(base->scheme, "file")) {
							debugf("Syntax violation (file otherwise 2) at %s\n", p);
						}
						// Set state to path state, and decrease pointer by one.
						state = PATH;
						p--;
				}
				break;
			case FILE_SLASH:
				// If c is "/" or "\", run these substeps:
				if (c == '/' || c == '\\') {
					// If c is "\", syntax violation.
					if (c == '\\') {
						debugf("Syntax violation (\\) at %s\n", p);
					}
					// Set state to file host state.
					state = FILE_HOST;
				// Otherwise, run these substeps:
				} else {
					// If base is non-null, base’s scheme is "file", and base’s path first string is a normalized Windows drive letter, append base’s path first string to url’s path.
					if (base && !strcmp(base->scheme, "file") && base->path_len >= 1 && is_normalized_windows_drive_letter(base->path[0])) {
						append_path(url, base->path[0]);
						// This is a (platform-independent) Windows drive letter quirk. Both url’s and base’s host are null under these conditions and therefore not copied.
					}
					// Set state to path state, and decrease pointer by one.
					state = PATH;
					p--;
				}
				break;
			case FILE_HOST:
				// If c is EOF code point, "/", "\", "?", or "#", decrease pointer by one, and run these substeps:
				if (c == 0 || c == '/' || c == '\\' || c == '?' || c == '#') {
					p--;
					buf[bufp] = 0;
					// If buffer is a Windows drive letter, syntax violation, set state to path state.
					if (is_windows_drive_letter(buf) && buf[2] == 0) {
						debugf("Syntax violation (file host 1.1) at %s\n", p);
						state = PATH;
						// This is a (platform-independent) Windows drive letter quirk. buffer is not reset here and instead used in the path state.
					// Otherwise, if buffer is the empty string, set state to path start state.
					} else if (bufp == 0) {
						state = PATH_START;
					// Otherwise, run these steps:
					} else {
						// Let host be the result of host parsing buffer.
						// If host is failure, return failure.
						url->host = (mcrawler_url_host *)malloc(sizeof (mcrawler_url_host));
						if (mcrawler_url_parse_host(url->host, buf) == MCRAWLER_URL_FAILURE) {
							return MCRAWLER_URL_FAILURE;
						}
						// If host is not "localhost", set url’s host to host.
						if (!strcmp(url->host->domain, "localhost")) {
							free(url->host);
							url->host = NULL;
						}
						// Set buffer to the empty string and state to path start state.
						bufp = 0;
						state = PATH_START;
					}
				// Otherwise, append c to buffer.
				} else {
					buf[bufp++] = c;
				}
				break;
			case PATH_START:
				// If url is special and c is "\", syntax violation.
				if (c == '\\' && is_special(url)) {
					debugf("Syntax violation (\\) at %s\n", p);
				}
				// Set state to path state, and if neither c is "/", nor url is special and c is "\", decrease pointer by one.
				state = PATH;
				if (c != '/' && !(c == '\\' && is_special(url))) {
					p--;
				}
				break;
			case PATH:
				// If one of the following is true
				if (
					// c is EOF code point or "/"
					(c == 0 || c == '/') ||
					// url is special and c is "\"
					(c == '\\' && is_special(url)) ||
					// state override is not given and c is "?" or "#"
					(c == '?' || c == '#')
				) {
					// If url is special and c is "\", syntax violation.
					if (c == '\\' && is_special(url)) {
						debugf("Syntax violation (\\) at %s\n", p);
					}
					buf[bufp] = 0;
					// If buffer is a double-dot path segment, pop url’s path, and then if neither c is "/", nor url is special and c is "\", append the empty string to url’s path.
					if (is_double_dot(buf)) {
						pop_path(url);
						if (c != '/' && !(c == '\\' && is_special(url))) {
							append_path(url, "");
						}
					// Otherwise, if buffer is a single-dot path segment and if neither c is "/", nor url is special and c is "\", append the empty string to url’s path.
					} else if (is_single_dot(buf)) {
						if (c != '/' && !(c == '\\' && is_special(url))) {
							append_path(url, "");
						}
					// Otherwise, if buffer is not a single-dot path segment, run these subsubsteps:
					} else {
						// If url’s scheme is "file", url’s path is empty, and buffer is a Windows drive letter, run these subsubsubsteps:
						if (url->path[0] == NULL && !strcmp(url->scheme, "file") && is_windows_drive_letter(buf) && buf[2] == 0) {
							// If url’s host is non-null, syntax violation.
							if (url->host) {
								debugf("Syntax violation (path 1.4.1.1) at %s\n", p);
								free(url->host);
							}
							// Set url’s host to null and replace the second code point in buffer with ":".
							url->host = NULL;
							buf[1] = ':';
							// This is a (platform-independent) Windows drive letter quirk.
						}
						// Append buffer to url’s path.
						append_path(url, buf);
					}
					// Set buffer to the empty string.
					bufp = 0;
					// If c is "?", set url’s query to the empty string, and state to query state.
					if (c == '?') {
						init_query(url);
						state = QUERY;
					}
					// If c is "#", set url’s fragment to the empty string, and state to fragment state.
					if (c == '#') {
						init_fragment(url);
						state = FRAGMENT;
					}
				// Otherwise, run these steps:
				} else {
					// If c is not a URL code point and not "%", syntax violation.

					// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.

					// If c is "%" and remaining, ASCII lowercased starts with "2e", append "." to buffer and increase pointer by two.
					if (c == '%' && p[1] == '2' && tolowercase(p[2]) == 'e') {
						buf[bufp++] = '.';
						p += 2;
					// Otherwise, UTF-8 percent encode c using the default encode set, and append the result to buffer.
					} else {
						if (is_default_encode_set(c)) {
							char encodedCodePoints[4];
							percent_encode(encodedCodePoints, c);
							strcpy(buf + bufp, encodedCodePoints);
							bufp += strlen(encodedCodePoints);
						} else {
							buf[bufp++] = c;
						}
					}
				}
				break;
			case CANNOT_BE_A_BASE_URL_PATH:
				// If c is "?", set url’s query to the empty string and state to query state.
				if (c == '?') {
					init_query(url);
					state = QUERY;
				// Otherwise, if c is "#", set url’s fragment to the empty string and state to fragment state.
				} else if (c == '#') {
					init_fragment(url);
					state = FRAGMENT;
				// Otherwise, run these substeps:
				} else {
					// If c is not EOF code point, not a URL code point, and not "%", syntax violation.

					// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.

					// If c is not EOF code point, UTF-8 percent encode c using the simple encode set, and append the result to the first string in url’s path.
					if (c != 0) {
						if (is_simple_encode_set(c)) {
							char encodedCodePoints[4];
							percent_encode(encodedCodePoints, c);
							append_path0_s(url, encodedCodePoints);
						} else {
							append_path0_c(url, c);
						}
					}
				}
				break;
			case QUERY:
				// If c is EOF code point, or state override is not given and c is "#", run these substeps:
				if (c == 0 || c == '#') {

					// If url is not special or url’s scheme is either "ws" or "wss", set encoding to UTF-8.
					// Set buffer to the result of encoding buffer using encoding.
					// For each byte in buffer run these subsubsteps:
					int query_p = strlen(url->query);
					for (int i = 0; i < bufp; i++) {
						// If byte is less than 0x21, greater than 0x7E, or is 0x22, 0x23, 0x3C, or 0x3E, append byte, percent encoded, to url’s query.
						if (buf[i] < 0x21 || buf[i] > 0x7E || buf[i] == 0x22 || buf[i] == 0x23 || buf[i] == 0x3C || buf[i] == 0x3E) {
							char encodedCodePoints[4];
							percent_encode(encodedCodePoints, buf[i]);
							append_query_s(url, &query_p, encodedCodePoints);
						// Otherwise, append a code point whose value is byte to url’s query.
						} else {
							append_query_c(url, &query_p, buf[i]);
						}
					}
					// Set buffer to the empty string.
					bufp = 0;
					// If c is "#", set url’s fragment to the empty string, and state to fragment state.
					if (c == '#') {
						init_fragment(url);
						state = FRAGMENT;
					}
				// Otherwise, run these substeps:
				} else {
					// If c is not a URL code point and not "%", syntax violation.
					// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.
					// Append c to buffer.
					buf[bufp++] = c;
				}
				break;
			case FRAGMENT:
				switch (c) {
					case 0:
						// Do nothing.
						break;
					// case U+0000
						// Syntax violation.
					default:
						// If c is not a URL code point and not "%", syntax violation.
						// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.
						// Append c to url’s fragment.
						append_fragment(url, c);
						// Unfortunately not using percent-encoding is intentional as implementations with majority market share exhibit this behavior.
				}
				break;
		}

	} while ((p < input || *p) && p++);

	return MCRAWLER_URL_SUCCESS;
}

void mcrawler_url_free_url(mcrawler_url_url *url) {
	free(url->scheme);
	free(url->username);
	free(url->password);
	free(url->query);
	free(url->fragment);
	free(url->object);
	if (url->path) {
		char *part, **p = url->path;
		while ((part = *p++)) {
			free(part);
		}
	}
	free(url->path);
	if (url->host) {
		free(url->host->domain);
	}
	free(url->host);
}

