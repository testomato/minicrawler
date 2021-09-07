#include <utility>
#include <string>
#include <vector>
#include <memory>

#include "minicrawler-url.h"

inline int is_ascii_alpha(unsigned char c) {
	return (0x41 <= c && c <= 0x5A) || (0x61 <= c && c <= 0x7A);
}

inline int is_ascii_digit(unsigned char c) {
	return 0x30 <= c && c <= 0x39;
}

inline int is_ascii_hexdigit(unsigned char c) {
	return is_ascii_digit(c) || (0x41 <= c && c <= 0x46) || (0x61 <= c && c <= 0x66);
}

inline int is_windows_drive_letter(const char *s) {
	return is_ascii_alpha(s[0]) && (s[1] == ':' || s[1] == '|');
}

inline int is_normalized_windows_drive_letter(const char *s) {
	return is_ascii_alpha(s[0]) && s[1] == ':' && s[3] == 0;
}

class Url {

	public:

		std::unique_ptr<mcrawler_url_host>& new_host() {
			d_host = std::make_unique<mcrawler_url_host>();
			return d_host;
		}

		void set_host(mcrawler_url_host *host) {
			if (!host) {
				d_host = nullptr;
				return;
			}

			mcrawler_url_host *dup = (mcrawler_url_host *)malloc(sizeof(mcrawler_url_host));
			memcpy(dup, host, sizeof(mcrawler_url_host));

			d_host = std::unique_ptr<mcrawler_url_host>(dup);
		}

		bool is_localhost() {
			if (d_host == nullptr) {
				return false;
			}
			return !strcmp(d_host->domain, "localhost");
		}

		const std::string& scheme() {
			return d_scheme;
		}

		void set_scheme(std::string &&scheme) {
			d_scheme = std::move(scheme);
			if (get_special_scheme_port() != 0) {
				d_special = true;
			}
		}

		void set_scheme(const char *scheme) {
			d_scheme.assign(scheme);
			if (get_special_scheme_port() != 0) {
				d_special = true;
			}
		}

		bool is_special() {
			return d_special;
		}

		int get_special_scheme_port() {
			if ("http" == d_scheme) return 80;
			if ("https" == d_scheme) return 443;
			if ("ftp" == d_scheme) return 21;
			if ("file" == d_scheme) return -1;
			if ("ws" == d_scheme) return 80;
			if ("wss" == d_scheme) return 443;
			return 0;
		}

		void cannot_be_a_base_url() {
			d_cannot_be_a_base_url = true;
		}

		void set_username(const char *username) {
			d_username.assign(username);
		}

		void append_username(const char *s) {
			d_username += s;
		}

		bool is_password_null() {
			return d_password == nullptr;
		}

		void set_password(std::string&& pass) {
			d_password = std::make_unique<std::string>(std::move(pass));
		}

		void set_password(const char *pass) {
			if (pass) {
				d_password = std::make_unique<std::string>(pass);
			} else {
				d_password = nullptr;
			}
		}

		void append_password(const char *s) {
			d_password->append(s);
		} 

		void set_port(unsigned int port) {
			d_port = port;
			d_port_not_null = true;
		}

		void set_port(nullptr_t) {
			d_port_not_null = false;
		}

		void set_port(unsigned int port, int not_null) {
			d_port = port;
			d_port_not_null = not_null == 1;
		}

		bool empty_path() {
			return d_path.empty();
		}

		void append_path(std::string&& path) {
			d_path.emplace_back(std::move(path));
		}

		void append_path(const char *path) {
			d_path.emplace_back(path);
		}

		void append_path0(const char *s) {
			if (d_path.size() == 0) {
				d_path.emplace_back(s);
			} else {
				d_path[0] += s;
			}
		}

		void append_path0(unsigned char c) {
			if (d_path.size() == 0) {
				d_path.emplace_back(1, c);
			} else {
				d_path[0].append(1, c);
			}
		}

		void replace_path(int len) {
			d_path.resize(len);
		}

		void replace_path(const char **path) {
			size_t len = 0;
			const char **p = path;
			while (*p++) len++;

			d_path.resize(len);
			for (int i = 0; i < len; i++) {
				d_path[i].assign(path[i]);
			}
		}

		void pop_path() {
			if (d_path.size() > 0) {
				d_path.pop_back();
			}
		}

		void shorten_path() {
			// if url’s scheme is not "file" or url’s path does not contain a
			// single string that is a normalized Windows drive letter, remove
			// url’s path’s last string, if any.
			if (d_scheme != "file" || !(d_path.size() == 1 &&
						is_normalized_windows_drive_letter(d_path[0].c_str()))) {
				pop_path();
			}
		}

		void set_query(std::string&& q) {
			d_query = std::make_unique<std::string>(std::move(q));
		}

		void set_query(const char *q) {
			if (q) {
				d_query = std::make_unique<std::string>(q);
			} else {
				d_query = nullptr;
			}
		}

		void append_query(const char *s) {
			if (d_query == nullptr) {
				d_query = std::make_unique<std::string>(s);
			} else {
				d_query->append(s);
			}
		}

		void append_query(unsigned char c) {
			if (d_query == nullptr) {
				d_query = std::make_unique<std::string>(1, c);
			} else {
				d_query->append(1, c);
			}
		}

		void set_fragment(std::string&& frag) {
			d_fragment = std::make_unique<std::string>(std::move(frag));
		}

		void set_fragment(const char *frag) {
			if (frag) {
				d_fragment = std::make_unique<std::string>(frag);
			} else {
				d_fragment = nullptr;
			}
		}

		void append_fragment(const char *s) {
			if (d_fragment == nullptr) {
				d_fragment = std::make_unique<std::string>(s);
			} else {
				d_fragment->append(s);
			}
		}

		void append_fragment(unsigned char c) {
			if (d_fragment == nullptr) {
				d_fragment = std::make_unique<std::string>(1, c);
			} else {
				d_fragment->append(1, c);
			}
		}

		void set_struct(mcrawler_url_url *url) {
			url->scheme = strdup(d_scheme.c_str());
			url->username = strdup(d_username.c_str());
			if (d_password != nullptr) {
				url->password = strdup(d_password->c_str());
			}
			if (d_host != nullptr) {
				url->host = (mcrawler_url_host *)malloc(sizeof(mcrawler_url_host));
				memcpy(url->host, d_host.get(), sizeof(mcrawler_url_host));
			}
			url->port = d_port;
			url->port_not_null = d_port_not_null ? 1 : 0;
			url->path = (char **)malloc((d_path.size()+1) * sizeof(char *));
			int i = 0;
			for (const std::string& p : d_path) {
				url->path[i++] = strdup(p.c_str());
			}
			url->path[i] = NULL;
			url->path_len = i;
			if (d_query != nullptr) {
				url->query = strdup(d_query->c_str());
			}
			if (d_fragment != nullptr) {
				url->fragment = strdup(d_fragment->c_str());
			}
			url->cannot_be_a_base_url = d_cannot_be_a_base_url ? 1 : 0;
		}


	private:
		std::unique_ptr<mcrawler_url_host> d_host;
		std::string d_scheme;
		std::string d_username;
		std::vector<std::string> d_path;
		std::unique_ptr<std::string> d_password;
		std::unique_ptr<std::string> d_query;
		std::unique_ptr<std::string> d_fragment;
		unsigned int d_port;
		bool d_port_not_null;
		bool d_special;
		bool d_cannot_be_a_base_url;
};
