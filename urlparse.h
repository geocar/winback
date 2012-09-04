struct url {
	char *schema;
	char *username;
	char *password;
	char *hostname;
	char *path;
	char *querystr;
	char *fragment;
	char *emailaddr;

	char *original_url;
	char *extra_free_me1;
	char *extra_free_me2;
	char *extra_free_me3;
	char *extra_free_me4;
	int port;
};
int url_parse(struct url *dst, const char *src);
void url_free(struct url *dst);

int netrc(struct url *p);
