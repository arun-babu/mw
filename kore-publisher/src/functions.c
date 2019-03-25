#include "kore-publisher.h"

extern int allow_admin_apis_from_other_hosts;

void
get_id (char *cn, char *id)
{
	int i, j;

	// my-email@example.com (my role) 

	for (i = 0; i < X509_CN_LENGTH && cn[i]; ++i)
	{
		switch (cn[i])
		{
			case '@':
				id[i] = '/';
				break;

			case ' ':
				id[i] = '\0';
				goto parse_role;
				break;
			
			default:
				id[i] = cn[i];
		}
	}

parse_role:

	j = i;

	++i;
	
	if (cn[i] != '(')
	{
		id[0] = '\0';
		return;
	}	
	
	id[j++] = '/';

	++i;

	for (; i < X509_CN_LENGTH && cn[i]; ++i)
	{
		switch (cn[i])
		{
			case ')':
				id[j++] = '\0'; 
				return;

			default:
				id[j++] = cn[i]; 
				break;
		}
	}
}

void
string_to_lower (const char *str)
{
	char *p = (char *)str;

	while (*p)
	{
		if (*p >= 'A' && *p <= 'Z')
			*p += 32; 

		++p;
	}
}

bool
is_request_from_localhost (struct http_request *req)
{
	if (allow_admin_apis_from_other_hosts)
		return true;

	switch (req->owner->family)
	{
		case AF_INET:
			if (req->owner->addr.ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
				return true;
			break;

		case AF_INET6:
			return false;
			break;
	}

	return false;
}

bool
is_json_safe (const char *string)
{
	size_t len = 0;

	char *p = (char *)string;

	while (*p)
	{
		if (! isprint(*p))
			return false;

		if (*p == '\'' || *p == '\\')
			return false;	

		++p;

		if (len > MAX_LEN_SAFE_JSON)
			return false;
	}

	return true;
}

bool
is_string_safe (const char *string)
{
	size_t len = 0;

	// string should not be NULL. let it crash if it is 
	const char *p = string;

	// assumption is that 'string' is in single quotes

	while (*p)
	{
		if (! isalnum (*p))
		{
			switch (*p)
			{
				/* allow these chars */
				case '-':
				case '/':
				case '.':
				case '*':
				case '#':
					break;

				default:
					return false;	
			}
		}

		++p;
		++len;

		// string is too long
		if (len > MAX_LEN_SAFE_STRING)
			return false;
	}

	return true;
}

bool
str_ends_with (const char *s1, const char *s2)
{
	// s1 has s2 at the end ?

	int s1_len = strnlen(s1,MAX_LEN_SAFE_STRING);
	int s2_len = strnlen(s2,MAX_LEN_SAFE_STRING);

	if (s2_len > s1_len)
		return false;

	int i = s1_len;
	int j = s2_len;

	while (j >= 0) 
	{
		if (s1[i--] != s2[j--])
			return false;
	}

	return true;
}
