#include "../h/config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <arpa/inet.h>
#ifdef HAVE_LIBICUUC
#include <unicode/uidna.h>
#endif

#include "minicrawler-url.h"
#include "url.hh"

#ifdef HAVE_DEBUG
#define debugf(...)   {fprintf(stderr, __VA_ARGS__);}
#else
#define debugf(...)
#endif

// shorthand name for MCRAWLER_URL_STATE_*
enum {
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
};

static void trim_controls_and_space(char *str) {
	size_t len = strlen(str);
	char *p = str;
	while (len > 0 && str[len-1]  > 0 && str[len-1] <= ' ') str[--len] = '\0';
	while (*p > 0 && *p <= ' ') p++;
	if (str != p) {
		memmove(str, p, len+1 - (p-str));
	}
}

static inline char tolowercase(unsigned char c) {
	return c >= 0x41 && c <= 0x5A ? c + (0x61-0x41) : c;
}

static inline int is_c0_encode_set(unsigned char c) {
	return c < 0x20 || c >= 0x7F;
}

static inline int is_frament_encode_set(unsigned char c) {
	return is_c0_encode_set(c) || c == 0x20 ||  c == '"' || c == '<' || c == '>' || c == '`';
}

static inline int is_query_encode_set(unsigned char c) {
	return is_c0_encode_set(c) || c == 0x20 ||  c == '"' || c == '#' || c == '<' || c == '>';
}

static inline int is_special_query_encode_set(unsigned char c) {
	return is_query_encode_set(c) || c == 0x27;
}

static inline int is_path_encode_set(unsigned char c) {
	return is_query_encode_set(c) || c == '?' || c == '`' || c == '{' || c == '}';
}

static inline int is_userinfo_encode_set(unsigned char c) {
	return is_path_encode_set(c) || c == '/' || c == ':' || c == ';' || c == '=' || c == '@' || c == '[' || c == ']' || c == '\\' || c == '^' || c == '|';
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
	// Let result be the result of running Unicode ToASCII with domain_name set
	// to domain, UseSTD3ASCIIRules set to beStrict, CheckHyphens set to false,
	// CheckBidi set to true, CheckJoiners set to true, Transitional_Processing
	// set to false, and VerifyDnsLength set to beStrict. 
	if (domain[0] == 0) {
		result[0] = 0;
		return MCRAWLER_URL_SUCCESS;
	}

#ifdef HAVE_LIBICUUC
	UErrorCode error = U_ZERO_ERROR;
	UIDNA *idna = uidna_openUTS46(
			UIDNA_CHECK_BIDI |
			UIDNA_CHECK_CONTEXTJ |
			UIDNA_NONTRANSITIONAL_TO_ASCII,
			&error);
	if (U_FAILURE(error)) {
		debugf("Error %s (%d) for %s\n", u_errorName(error), error, domain);
		return MCRAWLER_URL_FAILURE;
	}
	UIDNAInfo info = UIDNA_INFO_INITIALIZER;
	uidna_nameToASCII_UTF8(idna, domain, -1, result, length, &info, &error);
	uidna_close(idna);
	if (U_SUCCESS(error) && error != U_STRING_NOT_TERMINATED_WARNING && info.errors == 0) {
		return MCRAWLER_URL_SUCCESS;
	}
	if (U_FAILURE(error)) {
		debugf("Error %s (%d) for %s\n", u_errorName(error), error, domain);
	}
	return MCRAWLER_URL_FAILURE;
#else
	// If beStrict is false, domain is an ASCII string, and strictly splitting domain on U+002E (.) does not produce any item that starts with "xn--", this step is equivalent to ASCII lowercasing domain. 
	for (int i = 0; i < length; i++) {
		unsigned char c = domain[i];
		if (c > '\x7f') {
			debugf("Domain %s contains non-ascii characters\n", domain);
			return MCRAWLER_URL_FAILURE;
		} else if (c == '\0') {
			result[i] = c;

			if (!strncmp(result, "xn--", 4) || strstr(result, ".xn--") != NULL) {
				debugf("IDNA domains (%s) is not supported without libicu\n", domain);
				return MCRAWLER_URL_FAILURE;
			}
			return MCRAWLER_URL_SUCCESS;
		} else if (c >= 'A' && c <= 'Z') {
			result[i] = c + 32;
		} else {
			result[i] = c;
		}
	}

	debugf("Domain %s is longer than 255 characters\n", domain);
	return MCRAWLER_URL_FAILURE;
#endif
}

static inline int is_single_dot(char *s) {
	return !strcmp(s, ".") || !strcasecmp(s, "%2e");
}

static inline int is_double_dot(char *s) {
	return !strcmp(s, "..") || !strcasecmp(s, ".%2e") || !strcasecmp(s, "%2e.") || !strcasecmp(s, "%2e%2e");
}


int mcrawler_url_parse_ipv6(mcrawler_url_host *host, const char *input) {
	int numbers_seen;
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
	// Let numbersSeen be 0.
	numbers_seen = 0;
	// While c is not the EOF code point, run these substeps:
	while ((c = *p)) {
		// Let value be null.
		int value_null = 1;
		uint16_t value;

		// If numbersSeen is greater than 0, then:
		if (numbers_seen > 0) {
			// If c is a "." and numbersSeen is less than 4, then
			// increase pointer by one.
			if (c == '.' && numbers_seen < 4) {
			   c = *++p;
			//Otherwise, syntax violation, return failure.
			} else {
				debugf("IPv6 syntax violation (6.5.5.2.2) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
		}
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
			// If value is greater than 255, syntax violation, return failure.
			if (value > 255) {
				debugf("IPv6 syntax violation (10.3.4) at %s\n", p);
				return MCRAWLER_URL_FAILURE;
			}
			// Increase pointer by one.
			c = *++p;
		}
		// Set piece to piece × 0x100 + value.
		*p_piece = *p_piece * 0x100 + value;
		// Increase numbersSeen by one
		numbers_seen++;
		// If numbersSeen is 2 or 4, then increase piece pointer by one.
		if (numbers_seen == 2 || numbers_seen == 4) {
			c = *++p;
		}
		// If numbersSeen is not 4, syntax violation, return failure.
		if (numbers_seen != 4) {
			debugf("IPv6 syntax violation (6.5.6) at %s\n", p);
			return MCRAWLER_URL_FAILURE;
		}
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
	host->domain[0] = '[';
	mcrawler_url_serialize_ipv6(host, host->domain + 1);
	strcpy(host->domain + strlen(host->domain), "]");
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
	// If input is the empty string, then return zero.
	// 0x/0X is an IPv4 number apparently
	if (input[0] == '\0') {
		*number = 0;
		return MCRAWLER_URL_SUCCESS;
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
	mcrawler_url_serialize_ipv4(host, host->domain);
	free(parts[0]);
	return MCRAWLER_URL_SUCCESS;
}

int mcrawler_url_parse_host(mcrawler_url_host* host, const char *input) {
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
	// If asciiDomain contains U+0000, U+0009, U+000A, U+000D, U+0020, "#",
	// "%", "/", ":", "<", ">", "?", "@", "[", "\", "]", "^", or "|" syntax
	// violation, return failure.
	char *q;
	if ((q = strpbrk(asciiDomain, "\x09\x0A\x0D\x20#%/:<>?@[\\]^|"))) {
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
	strcpy(host->domain, asciiDomain);
	return MCRAWLER_URL_SUCCESS;
}

int mcrawler_url_parse2(mcrawler_url_url *u, const char *input_arg, const mcrawler_url_url *base, mcrawler_url_parse_state *state_arg)
{
	if (!input_arg) {
		return MCRAWLER_URL_FAILURE;
	}

    Url url = Url();

    char *input = strdup(input_arg);

    // Remove any leading and trailing C0 controls and space from input.
    trim_controls_and_space(input);

	char *p;
    size_t len = strlen(input);

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
	int state = SCHEME_START;

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
					url.set_scheme(buf);
					// Set buffer to the empty string.
					bufp = 0;
					// If url’s scheme is "file", run these subsubsteps:
					if ("file" == url.scheme()) {
						// If remaining does not start with "//", syntax violation.
						if (p[1] != '/' || p[2] != '/') {
							debugf("syntax violation (scheme 2.5.1) at %s\n", p);
						}
						// Set state to file state.
						state = FILE_STATE;
					// Otherwise, if url is special, base is non-null, and base’s scheme is equal to url’s scheme, set state to special relative or authority state.
					} else if (url.is_special()) {
						if (base && url.scheme() == base->scheme) {
							state = SPECIAL_RELATIVE_OR_AUTHORITY;
						// Otherwise, if url is special, set state to special authority slashes state.
						} else {
							state = SPECIAL_AUTHORITY_SLASHES;
						}
					// Otherwise, if remaining starts with an "/", set state to path or authority state, and increase pointer by one.
					} else if (p[1] == '/') {
						state = PATH_OR_AUTHORITY;
						p++;
					// Otherwise, set url’s cannot-be-a-base-URL flag, append an empty string to url’s path, and set state to cannot-be-a-base-URL path state.
					} else {
						url.cannot_be_a_base_url();
						url.append_path("");
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
				// If base is null, or base’s cannot-be-a-base-URL flag is set and c is not "#", syntax violation, return failure.
				if (!base || (base->cannot_be_a_base_url && c != '#')) {
					debugf("Syntax violation (no scheme 1) at %s\n", p);
                    goto failed;
				// Otherwise, if base’s cannot-be-a-base-URL flag is set and c is "#", set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, set url’s cannot-be-a-base-URL flag, and set state to fragment state.
				} else if (base->cannot_be_a_base_url && c == '#') {
					url.set_scheme(base->scheme);
					url.replace_path((const char **)base->path);
					url.set_query(base->query);
					url.set_fragment("");
					url.cannot_be_a_base_url();
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
				url.set_scheme(base->scheme);
				switch (c) {
					case 0:
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, and url’s query to base’s query.
						url.set_username(base->username);
						url.set_password(base->password);
						url.set_host(base->host);
						url.set_port(base->port, base->port_not_null);
						url.replace_path((const char **)base->path);
						url.set_query(base->query);
						break;
					case '/':
						// Set state to relative slash state.
						state = RELATIVE_SLASH;
						break;
					case '?':
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, url’s query to the empty string, and state to query state.
						url.set_username(base->username);
						url.set_password(base->password);
						url.set_host(base->host);
						url.set_port(base->port, base->port_not_null);
						url.replace_path((const char **)base->path);
						url.set_query("");
						state = QUERY;
						break;
					case '#':
						// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, and state to fragment state.
						url.set_username(base->username);
						url.set_password(base->password);
						url.set_host(base->host);
						url.set_port(base->port, base->port_not_null);
						url.replace_path((const char **)base->path);
						url.set_query(base->query);
						url.set_fragment("");
						state = FRAGMENT;
						break;
					default:
						// If url is special and c is "\", syntax violation, set state to relative slash state.
						if (c == '\\' && url.is_special()) {
							debugf("Syntax violation (relative) at %s\n", p);
							state = RELATIVE_SLASH;
						} else {
							// Set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, url’s path to base’s path, and then remove url’s path’s last entry, if any.
							url.set_username(base->username);
							url.set_password(base->password);
							url.set_host(base->host);
                            url.set_port(base->port, base->port_not_null);
							url.replace_path((const char **)base->path);
							url.pop_path();
							// Set state to path state, and decrease pointer by one.
							state = PATH;
							p--;
						}
				}
				break;
			case RELATIVE_SLASH:
				// If url is special and c is "/" or "\", then:
				if ((c == '/' || c == '\\') && url.is_special()) {
					// If c is "\", syntax violation.
					if (c == '\\') {
						debugf("Syntax violation (relative slash 1.1) at %s\n", p);
					}
					// Set state to special authority ignore slashes state.
					state = SPECIAL_AUTHORITY_IGNORE_SLASHES;
				// Otherwise, if c is "/", then set state to authority state.
				} else if (c == '/') {
					state = AUTHORITY;
				// Otherwise, set url’s username to base’s username, url’s password to base’s password, url’s host to base’s host, url’s port to base’s port, state to path state, and then, decrease pointer by one.
				} else {
					url.set_username(base->username);
					url.set_password(base->password);
					url.set_host(base->host);
                    url.set_port(base->port, base->port_not_null);
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
					for (int i = 0; i < bufp; i++) {
						// If codePoint is ":" and url’s password is null, set url’s password to the empty string and run these substeps for the next code point.
						if (buf[i] == ':' && url.is_password_null()) {
                            url.set_password("");
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
						if (!url.is_password_null()) {
                            url.append_password(encodedCodePoints);
						} else {
                            url.append_username(encodedCodePoints);
						}
					}
					// Set buffer to the empty string.
					bufp = 0;

				// Otherwise, if one of the following is true
				} else if (
					// c is EOF code point, "/", "?", or "#"
					(c == 0 || c == '/' || c == '?' || c == '#') ||
					// url is special and c is "\"
					(c == '\\' && url.is_special())
				) {
					// then run these substeps:
					// 
					// If @ flag is set and buffer is the empty string,
					// syntax violation, return failure.
					if (flag_at == 1 && bufp == 0) {
						debugf("Syntax violation (authority 2.1) at %s\n", p);
                        goto failed;
					}
					// Decrease pointer by the number of code points in buffer plus
					// one, set buffer to the empty string, and set state to
					// host state.
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
					// If buffer is the empty string, syntax violation, return failure.
					if (bufp == 0) {
                        goto failed;
					}
					// 
					// Let host be the result of host parsing buffer with url is special.
					// If host is failure, then return failure.
					buf[bufp] = 0;
					if (mcrawler_url_parse_host(url.new_host().get(), buf) == MCRAWLER_URL_FAILURE) {
                        goto failed;
					}
					// Set url’s host to host, buffer to the empty string, and state to port state.
					bufp = 0;
					state = PORT;
				// Otherwise, if one of the following is true
				} else if (
					// c is EOF code point, "/", "?", or "#"
					(c == 0 || c == '/' || c == '?' || c == '#') ||
					// url is special and c is "\"
					(c == '\\' && url.is_special())
				) {
					// then decrease pointer by one, and run these substeps:
					p--;
					// If url is special and buffer is the empty string, syntax vialotion, return failure.
					if (bufp == 0 && url.is_special()) {
                        goto failed;
					}
					// Let host be the result of host parsing buffer with url is special.
					// If host is failure, then return failure.
					buf[bufp] = 0;
					if (mcrawler_url_parse_host(url.new_host().get(), buf) == MCRAWLER_URL_FAILURE) {
                        goto failed;
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
					(c == '\\' && url.is_special())
				) {
					// If buffer is not the empty string, run these subsubsteps:
					if (bufp) {
						// Let port be the mathematical integer value that is represented by buffer in radix-10 using ASCII digits for digits with values 0 through 9.
						buf[bufp] = 0;
						long port = atol(buf);
						// If port is greater than 2^16 − 1, syntax violation, return failure.
						if (port > (1L<<16) - 1) {
							debugf("Syntax violation (port 2.1.2) at %s\n", p);
                            goto failed;
						}
						// Set url’s port to null, if port is url’s scheme’s default port, and to port otherwise.
						if (url.get_special_scheme_port() == port) {
                            url.set_port(nullptr);
						} else {
                            url.set_port(port);
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
                    goto failed;
				}
				break;
			case FILE_STATE:
				// Set url’s scheme to "file".
				url.set_scheme("file");
				// Set url’s host to the empty string.
                url.new_host();
				// If c is U+002F (/) or U+005C (\), then:
				if (c == '/' || c == '\\') {
					// If c is U+005C (\), validation error.
					// Set state to file slash state.
					state = FILE_SLASH;
				// Otherwise, if base is non-null and base’s scheme is "file":
				} else if (base && !strcmp(base->scheme, "file")) {
					// Set url’s host to base’s host, url’s path to a clone of
					// base’s path, and url’s query to base’s query.
                    url.set_host(base->host);
					url.replace_path((const char **)base->path);
					url.set_query(base->query);
					// If c is U+003F (?), then set url’s query to the empty
					// string and state to query state.
					if (c == '?') {
						url.set_query("");
						state = QUERY;
					// Otherwise, if c is U+0023 (#), set url’s fragment to the
					// empty string and state to fragment state.
					} else if (c == '#') {
						url.set_fragment("");
						state = FRAGMENT;
					// Otherwise, if c is not the EOF code point:
					} else if (c != 0) {
						// Set url’s query to null.
                        url.set_query(nullptr);
						// If the substring from pointer in input does not
						// start with a Windows drive letter, then shorten
						// url’s path.
						if (!is_windows_drive_letter(p)) {
							url.shorten_path();
						// Otherwise:
						} else {
							// Validation error.
							// Set url’s path to an empty list.
                            url.replace_path(0);
						}
						// Set state to path state and decrease pointer by 1.
						state = PATH;
						p--;
					}
				// Otherwise, set state to path state, and decrease pointer by 1.
				} else {
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
					// If base is non-null and base’s scheme is "file", then: 
					if (base && !strcmp(base->scheme, "file")) {
						// Set url’s host to base’s host.
						url.set_host(base->host);
						// If the substring from pointer in input does not
						// start with a Windows drive letter and base’s path[0]
						// is a normalized Windows drive letter, then append
						// base’s path[0] to url’s path.
						if (!is_windows_drive_letter(p)
							&& base->path_len >= 1 && is_normalized_windows_drive_letter(base->path[0]))
						{
							url.append_path(base->path[0]);
							// This is a (platform-independent) Windows drive letter quirk.
						}
					}
					// Set state to path state, and decrease pointer by 1.
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
						if (mcrawler_url_parse_host(url.new_host().get(), buf) == MCRAWLER_URL_FAILURE) {
							goto failed;
						}
						// If host is not "localhost", set url’s host to host.
						if (url.is_localhost()) {
                            url.set_host(nullptr);
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
				// If url is special, then:
				if (url.is_special()) {
					// If c is "\", syntax violation.
					if (c == '\\') {
						debugf("Syntax violation (\\) at %s\n", p);
					}
					// Set state to path state.
					state = PATH;
					// If c is neither "/" nor "\", then decrease
					// pointer by one.
					if (c != '/' && c != '\\') {
						p--;
					}
				// Otherwise, if state override is not given and c is "?",
				// then set url's query to the empty string and state to
				// query state.
				} else if (c == '?') {
					url.set_query("");
					state = QUERY;
				// Otherwise, if state override is not given and c is "#",
				// then set url's fragment to the empty string and state to
				// fragment state.
				} else if (c == '#') {
					url.set_fragment("");
					state = FRAGMENT;
				// Otherwise, if c is not EOF code point, then: set state to
				// path state and if c is not "/", then decrease pointer by
				// one.
				} else if (c != 0) {
					state = PATH;
					if (c != '/') {
						p--;
					}
				}
				break;
			case PATH:
				// If one of the following is true
				if (
					// c is EOF code point or "/"
					(c == 0 || c == '/') ||
					// url is special and c is "\"
					(c == '\\' && url.is_special()) ||
					// state override is not given and c is "?" or "#"
					(c == '?' || c == '#')
				) {
					// If url is special and c is "\", syntax violation.
					if (c == '\\' && url.is_special()) {
						debugf("Syntax violation (\\) at %s\n", p);
					}
					buf[bufp] = 0;
					// If buffer is a double-dot path segment
					if (is_double_dot(buf)) {
						// Shorten url's path
						url.shorten_path();
						// If neither c is U+002F (/), nor url is special and c
						// is U+005C (\), append the empty string to url's
						// path.
						//
						// This means that for input /usr/.. the result is /
						// and not a lack of a path.
						if (c != '/' && !(c == '\\' && url.is_special())) {
							url.append_path("");
						}
					// Otherwise, if buffer is a single-dot path segment and if neither c is "/", nor url is special and c is "\", append the empty string to url’s path.
					} else if (is_single_dot(buf)) {
						if (c != '/' && !(c == '\\' && url.is_special())) {
							url.append_path("");
						}
					// Otherwise, if buffer is not a single-dot path segment, run these subsubsteps:
					} else {
						// If url’s scheme is "file", url’s path is empty, and buffer is a Windows drive letter,
						if (url.empty_path() && url.scheme() == "file" && is_windows_drive_letter(buf) && buf[2] == 0) {
							// Replace the second code point in buffer with ":".
							buf[1] = ':';
							// This is a (platform-independent) Windows drive letter quirk.
						}
						// Append buffer to url’s path.
						url.append_path(buf);
					}
					// Set buffer to the empty string.
					bufp = 0;
					// If c is "?", set url’s query to the empty string, and state to query state.
					if (c == '?') {
						url.set_query("");
						state = QUERY;
					}
					// If c is "#", set url’s fragment to the empty string, and state to fragment state.
					if (c == '#') {
						url.set_fragment("");
						state = FRAGMENT;
					}
				// Otherwise, run these steps:
				} else {
					// If c is not a URL code point and not "%", syntax violation.

					// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.

					// UTF-8 percent encode c using the default encode set, and append the result to buffer.
					if (is_path_encode_set(c)) {
						char encodedCodePoints[4];
						percent_encode(encodedCodePoints, c);
						strcpy(buf + bufp, encodedCodePoints);
						bufp += strlen(encodedCodePoints);
					} else {
						buf[bufp++] = c;
					}
				}
				break;
			case CANNOT_BE_A_BASE_URL_PATH:
				// If c is "?", set url’s query to the empty string and state to query state.
				if (c == '?') {
					url.set_query("");
					state = QUERY;
				// Otherwise, if c is "#", set url’s fragment to the empty string and state to fragment state.
				} else if (c == '#') {
					url.set_fragment("");
					state = FRAGMENT;
				// Otherwise, run these substeps:
				} else {
					// If c is not EOF code point, not a URL code point, and not "%", syntax violation.

					// If c is "%" and remaining does not start with two ASCII hex digits, syntax violation.

					// If c is not EOF code point, UTF-8 percent encode c using the simple encode set, and append the result to the first string in url’s path.
					if (c != 0) {
						if (is_c0_encode_set(c)) {
							char encodedCodePoints[4];
							percent_encode(encodedCodePoints, c);
							url.append_path0(encodedCodePoints);
						} else {
							url.append_path0(c);
						}
					}
				}
				break;
			case QUERY:
				// If encoding is not UTF-8 and one of the following is true:
					// url is not special
					// url’s scheme is "ws" or "wss"
				// then set encoding to UTF-8.

				// If one of the following is true:
				// state override is not given and c is U+0023 (#)
				// c is the EOF code point
				if (c == 0 || c == '#') {
					// Let queryPercentEncodeSet be the special-query
					// percent-encode set if url is special; otherwise the
					// query percent-encode set.
					for (int i = 0; i < bufp; i++) {
						// Percent-encode after encoding, with encoding,
						// buffer, and queryPercentEncodeSet, and append the
						// result to url’s query.
						if (is_query_encode_set(buf[i]) || url.is_special() && is_special_query_encode_set(buf[i])) {
							char encodedCodePoints[4];
							percent_encode(encodedCodePoints, buf[i]);
							url.append_query(encodedCodePoints);
						} else {
							url.append_query(buf[i]);
						}
					}
					// Set buffer to the empty string.
					bufp = 0;
					// If c is U+0023 (#), then set url’s fragment to the empty
					// string and state to fragment state.
					if (c == '#') {
						url.set_fragment("");
						state = FRAGMENT;
					}
				// Otherwise, if c is not the EOF code point:
				} else if (c != 0) {
					// If c is not a URL code point and not U+0025 (%),
					// validation error.
					// If c is U+0025 (%) and remaining does not start with two
					// ASCII hex digits, validation error.
					// Append c to buffer.
					buf[bufp++] = c;
				}
				break;
			case FRAGMENT:
				// If c is not the EOF code point, then:
				if (c != 0) {
					// If c is not a URL code point and not U+0025 (%),
					// validation error.
					// If c is U+0025 (%) and remaining does not start with two
					// ASCII hex digits, validation error.
					// UTF-8 percent-encode c using the fragment percent-encode
					// set and append the result to url’s fragment.
					if (is_frament_encode_set(c)) {
						char encodedCodePoints[4];
						percent_encode(encodedCodePoints, c);
						url.append_fragment(encodedCodePoints);
					} else {
						url.append_fragment(c);
					}
				}
				break;
		}

	} while ((p < input || *p) && p++);

    url.set_struct(u);
    if (state_arg != NULL) {
        *state_arg = static_cast<mcrawler_url_parse_state>(state);
    }
    free(input);
	return MCRAWLER_URL_SUCCESS;

failed:
    if (state_arg != NULL) {
        *state_arg = static_cast<mcrawler_url_parse_state>(state);
    }
    free(input);
	return MCRAWLER_URL_FAILURE;
}

int mcrawler_url_parse(mcrawler_url_url *url, const char *input, const mcrawler_url_url *base)
{
	return mcrawler_url_parse2(url, input, base, NULL);
}
