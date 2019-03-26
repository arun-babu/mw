#include "kore-publisher.h"
#include "assets.h"

#define X509_CN_LENGTH (64)

char cn[X509_CN_LENGTH + 1];

struct kore_pgsql sql;

struct kore_buf *query 		= NULL;
struct kore_buf *response 	= NULL;

bool is_success				= false;
bool allow_admin_apis_from_other_hosts	= false;

char *postgres_pwd;

char error_string [1025];

int
init (int state)
{
	// mask server name 
	http_server_version("");

	if (! (postgres_pwd = getenv("POSTGRES_PWD")))
	{
		fprintf(stderr,"postgres password not set\n");
		return KORE_RESULT_ERROR;
	}
	unsetenv("POSTGRES_PWD");

	/* By default we allow admin APIs to be called from any hosts.
	   Admin must unset the ALLOW_ADMIN_APIS_FROM_OTHER_HOSTS 
	   environment variable to only allow it from localhost. */

	if (getenv("ALLOW_ADMIN_APIS_FROM_OTHER_HOSTS"))
		allow_admin_apis_from_other_hosts = true;

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(1024*1024);

	char connection_str[129];
        snprintf (
			connection_str,
			129,
			"host = %s user = postgres password = %s",
			"postgres",
			postgres_pwd
	);

	kore_pgsql_register("db",connection_str);

	printf("===> Worker [%d]'s initialization OK\n",worker->id);

	return KORE_RESULT_OK;
}

bool
looks_like_a_valid_CN (const char *str)
{
	// should not contain '/'
	return true;
}

bool is_alpha_numeric(const char *str)
{
	return true;
}

bool
is_owner (const char *id, const char *resource)
{
	return true;
}

int
search_catalog (struct http_request *req)
{
	int i, num_rows;

	const char *tag;
	const char *entity;

	const char *key;
	const char *value;

	const char *body = req->http_body ? (char *)req->http_body->data : NULL;

	req->status = 403;

	http_populate_get(req);

	if (req->http_body_length > MAX_LEN_SAFE_JSON)
		BAD_REQUEST("body too long");

	if (http_argument_get_string(req,"id",(void *)&entity))
	{
		if (! is_string_safe(entity))
			BAD_REQUEST("invalid entity");

		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id='%s'",
					entity
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (http_argument_get_string(req,"tag",(void *)&tag))
	{
		if (! is_string_safe(tag))	
			BAD_REQUEST("invalid tag");

		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id LIKE '%%/%%' "
				"AND jsonb_typeof(schema->'tags') = 'array' " 
				"AND ("
					"(schema->'tags' ? LOWER('%s'))"
						" OR "
					"(schema->'tags' ? '%s')"
				") "
				"ORDER BY id",
					tag, 
					tag 
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (http_argument_get_string(req,"key",(void *)&key))
	{
		if (! http_argument_get_string(req,"value",(void *)&value))
			BAD_REQUEST("value field missing");
			
		if (! is_string_safe(key))	
			BAD_REQUEST("invalid key");

		if (! is_string_safe(value))	
			BAD_REQUEST("invalid value");

		// convert . to ,
		char *p = key;
		while (*p)
		{
			if (*p == '.')
				*p = ',';
			++p;
		}

		// remove all starting and trailing double quotes and remove spaces
		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id LIKE '%%/%%' "
				"AND TRIM(RTRIM(LTRIM((schema #> '{%s}')::TEXT,'\"'),'\"')) = '%s' " 
				"ORDER BY id",
					key,
					value
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (body)
	{
		if (! is_json_safe(body))
			BAD_REQUEST("bad json input");

		CREATE_STRING (query,
			"SELECT id,schema FROM users WHERE schema @> '$1'::jsonb"
		);

		kore_pgsql_cleanup(&sql);
		kore_pgsql_init(&sql);

		if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
		{
			kore_pgsql_logerror(&sql);
			ERROR("DB error while setup");
		}

		if ( 
			! kore_pgsql_query_params (
				&sql,
				(char *)query->data,
				0,
				1,
				body,
				req->http_body_length,
				0
			)
		)
		{
			printf("[%d] Error in query {%s}\n",__LINE__,query->data);
			kore_pgsql_logerror(&sql);
			ERROR("failed to query catalog schema using body");
		}
	}
	else
	{
		BAD_REQUEST("inputs for the API are missing");
	}

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *id	= kore_pgsql_getvalue(&sql,i,0);
		char *schema 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,"\"%s\":%s,",id,schema);
	} 

	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
catalog_tags (struct http_request *req)
{
	int i, num_rows;

	req->status = 403;

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	CREATE_STRING (query,

		// 1. remove () from (tag),
		// 2. remove front and end spaces
		// 3. limit tag length to 30
		// 4. ignore the ones with double quotes in tags 

		"SELECT RTRIM(LTRIM(tag::TEXT,'('),')') as final_tag,"
		"COUNT(tag) as tag_count FROM ("
			"SELECT SUBSTRING(TRIM(LOWER(jsonb_array_elements_text(schema->'tags')::TEXT)) for 30) "
			"FROM users WHERE jsonb_typeof(schema->'tags') = 'array'"
		") AS tag WHERE tag::TEXT NOT LIKE '%%\"%%' group by final_tag order by tag_count DESC"
	);

	RUN_QUERY (query,"could not query catalog");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *tag 	= kore_pgsql_getvalue(&sql,i,0);
		char *count 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,"\"%s\":%s,",tag,count);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
catalog (struct http_request *req)
{
	switch (req->method)
	{
		case HTTP_METHOD_GET:
			return get_catalog(req);

		case HTTP_METHOD_PUT:
		case HTTP_METHOD_POST:
			return post_catalog(req);

		case HTTP_METHOD_DELETE:
			return delete_catalog(req);

		default:
			BAD_REQUEST("invalid http method");
	}

done:
	END();
}

int
get_catalog (struct http_request *req)
{
	int i, num_rows;

	const char *id;
	const char *apikey;

	req->status = 403;

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	CREATE_STRING (query,
		"SELECT masked_id,schema FROM users WHERE schema IS NOT NULL ORDER BY id"
	);

	RUN_QUERY (query,"unable to query catalog data");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity_id	= kore_pgsql_getvalue(&sql,i,0);
		char *schema 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,"\"%s\":%s,",entity_id,schema);
	} 

	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
post_catalog (struct http_request *req)
{
	const char *entity;

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "entity", &entity)
			,
		"entity name missing in headers"
	);

	string_to_lower(entity);

	// entity at the time of registration is simple alapha numeric
	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

	char *body = req->http_body ? (char *)req->http_body->data : NULL;

	if (! body)
		BAD_REQUEST("no json body found");

	if (req->http_body_length > MAX_LEN_SAFE_JSON)
		BAD_REQUEST("schema too long");

	if (! is_json_safe(body))
		BAD_REQUEST("bad json input");

	if (X509_GET_CN(req->owner->cert, cn, sizeof(cn)) == -1)
		FORBIDDEN("No CN found in the certificate");

/////////////////////////////////////////////////

	if (! looks_like_a_valid_CN(cn))
		BAD_REQUEST("invalid CN in certificate");

/////////////////////////////////////////////////

	printf("Starting ...\n");
	CREATE_STRING (query,
		"INSERT INTO users(id,masked_id,schema) "
		"VALUES('%s/%s',concat(encode(digest(split_part('%s','@',1),'sha1'),'hex'),'@',split_part('%s','@',2),'/','%s'),$1)",
				// $1 is the schema (in body) 
		cn,
		entity,
		cn,
		cn,
		entity
	);

	printf("[%d] Error in query {%s}\n",__LINE__,query->data);

	kore_pgsql_cleanup(&sql);
	kore_pgsql_init(&sql);

	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
	{
		kore_pgsql_logerror(&sql);
		ERROR("DB error while setup");
	}

	if ( 
		! kore_pgsql_query_params (
			&sql,
			(char *)query->data,
			0,
			1,
			body,
			req->http_body_length,
			0
		)
	)
	{
		kore_pgsql_logerror(&sql);
		ERROR("failed to create the entity with schema");
	}
	
	kore_buf_reset(response);

	OK_201();

done:
	END();
}

int
delete_catalog (struct http_request *req)
{
	const char *entity;

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "entity", &entity)
			,
		"entity name missing in headers"
	);

	string_to_lower(entity);

	// entity at the time of registration is simple alapha numeric
	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

	if (X509_GET_CN(req->owner->cert, cn, sizeof(cn)) == -1)
		FORBIDDEN("No CN found in the certificate");

/////////////////////////////////////////////////

	if (! looks_like_a_valid_CN(cn))
		BAD_REQUEST("invalid CN in certificate");

/////////////////////////////////////////////////

	CREATE_STRING (query,
		"DELETE FROM users WHERE id ='%s/%s'",
		cn,
		entity
	);

	printf("Query = {%s}\n",query->data);

	RUN_QUERY(query,"could not delete the entity");

	kore_buf_reset(response);
	
	OK();
done:
	END();
}

int
get_owners(struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this API can only be called from localhost");

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	CREATE_STRING (query, "SELECT id,blocked FROM users WHERE id NOT LIKE '%%/%%' ORDER BY id");
	RUN_QUERY(query,"failed to query user table");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	for (i = 0; i < num_rows; ++i)
	{
		char *owner		= kore_pgsql_getvalue(&sql,i,0);
		char *is_blocked	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf (
			response,
				"\"%s\":%s,",
					owner,	
					is_blocked [0] == 't' ? "1" : "0"
		);
	}

	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
follow (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *from;
	const char *to;

	const char *topic; // topics the subscriber is interested in

	const char *validity; // in hours 

	const char *message_type;

	char *status = "pending";

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "to", &to)
				||
		! http_request_header(req, "validity", &validity)
				||
		! http_request_header(req, "topic", &topic)
				||
		! http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	BAD_REQUEST_if (
		(strcmp(message_type,"command") 	!= 0) &&
		(strcmp(message_type,"protected") 	!= 0) &&
		(strcmp(message_type,"diagnostics") 	!= 0)
		,
		"invalid message-type"
	);

	if (1)
	{
		if (! http_request_header(req, "from", &from))
			BAD_REQUEST("'from' value missing in header");

		// check if the he is the owner of from 
		if (! is_owner(id,from))
			FORBIDDEN("you are not the owner of 'from' entity");
	}
	else
	{
		// from is itself 
		from = id;
	}

/////////////////////////////////////////////////

	if (! is_string_safe(from))
		BAD_REQUEST("invalid from");

	if (! is_string_safe(to))
		BAD_REQUEST("invalid to");

	if (! is_string_safe(validity))
		BAD_REQUEST("invalid validity");

	if (! is_string_safe(topic))
		BAD_REQUEST("invalid topic");

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	// if both from and to are owned by id
	if (is_owner(id,to))
		status = "approved";

	int int_validity = strtonum(validity,1,10000,NULL);
	if (int_validity <= 0)
		BAD_REQUEST("validity must be in number of hours");

	CREATE_STRING (query,
		"SELECT is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				to	
	);

	RUN_QUERY (query,"could not get info about 'to'");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("'to' does not exist OR has been blocked");

	char *char_is_to_autonomous	= kore_pgsql_getvalue(&sql,0,0);
	bool is_to_autonomous		= char_is_to_autonomous[0] == 't';

	CREATE_STRING (query, 
		"INSERT INTO follow "
		"(follow_id,requested_by,from_id,exchange,time,topic,validity,status) "
		"VALUES(DEFAULT,'%s','%s','%s.%s',NOW(),'%s','%d','%s')",
			id,
			from,
			to,
			message_type,
			topic,
			int_validity,
			status
	);

	RUN_QUERY (query, "failed to insert follow");

	CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
	RUN_QUERY 	(query,"failed pg_get_serial");

	const char *follow_id = kore_pgsql_getvalue(&sql,0,0);

	if (strcmp(status,"approved") == 0)
	{
		// add entry in acl
		CREATE_STRING (query,
			"INSERT INTO acl "
			"(acl_id,from_id,exchange,follow_id,topic,valid_till) "
			"VALUES(DEFAULT,'%s','%s.%s','%s','%s',NOW() + interval '%d hours')",
		        	from,
				to,
				message_type,
				follow_id,
				topic,
				int_validity
		);

		RUN_QUERY (query,"could not run insert query on acl");

		req->status = 200;
	}
	else
	{
		char *subject = "Request for follow";

		char message[1025];
		// snprintf(message,  1025, "'%s' has requested access to '%s'",id,to);

		/* we have sent the request,
		   but the owner of the "to" device/app must approve */
		req->status = 202;
	}

	kore_buf_reset(response);
	kore_buf_appendf(response,"{\"follow-id\":\"%s\"}\n",follow_id);

done:

	END();
}

int
unfollow (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *follow_id;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (1)
	{
		CREATE_STRING (query,
			"SELECT "
			"from_id,exchange,topic "
			"FROM follow "
			"WHERE follow_id = '%s' AND from_id LIKE '%s/%%' "
			"ORDER BY time DESC",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"from_id,exchange,topic "
			"FROM follow "
			"WHERE follow_id = '%s' AND from_id = '%s' "
			"ORDER BY time DESC",
				follow_id,
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	if (num_rows != 1)
		FORBIDDEN("unauthorized");

	char *from_id 		= kore_pgsql_getvalue(&sql,0,0);
	char *my_exchange	= kore_pgsql_getvalue(&sql,0,1);
	char *topic		= kore_pgsql_getvalue(&sql,0,2);

	CREATE_STRING (query,
				"SELECT 1 FROM acl "
				"WHERE follow_id = '%s' ",
					follow_id
	);

	RUN_QUERY(query,"failed to query acl table for permission");

	if (kore_pgsql_ntuples(&sql) != 1)
		FORBIDDEN("unauthorized");

	CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from follow table");
		
	CREATE_STRING 	(query, "DELETE FROM acl WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from acl table");

	OK();

done:
	END();
}

int
share (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *follow_id;

	req->status = 403;
	kore_buf_reset(response);

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (1)
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,validity,topic FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' and status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,validity,topic FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' and status='pending'",
				follow_id,
				id
		);
	}

	RUN_QUERY (query,"could not run select query on follow");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("follow-id is not valid");

	char *from_id		= kore_pgsql_getvalue(&sql,0,0);
	char *my_exchange 	= kore_pgsql_getvalue(&sql,0,1);
	char *validity_hours 	= kore_pgsql_getvalue(&sql,0,2);
	char *topic 	 	= kore_pgsql_getvalue(&sql,0,3); 

	CREATE_STRING (query,
		"SELECT is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				from_id	
	);

	RUN_QUERY (query,"could not get info about 'from'");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("'from' does not exist OR has been blocked");

	char *char_is_from_autonomous	= kore_pgsql_getvalue(&sql,0,0);
	bool is_from_autonomous		= char_is_from_autonomous[0] == 't';

	// NOTE: follow_id is primary key 
	CREATE_STRING (query,
			"UPDATE follow SET status='approved' WHERE follow_id = '%s'",
				follow_id
	);
	RUN_QUERY (query,"could not run update query on follow");

	// add entry in acl
	CREATE_STRING (query,
		"INSERT INTO acl (acl_id,from_id,exchange,follow_id,topic,valid_till) "
		"VALUES(DEFAULT,'%s','%s','%s','%s',NOW() + interval '%s hours')",
			from_id,
			my_exchange,
			follow_id,
			topic,
			validity_hours
	);

	RUN_QUERY (query,"could not run insert query on acl");

	char *subject = "Approved follow request";

	char message[1025];
	// snprintf(message, 1025, "'%s' has approved follow request for access on '%s'",id,bind_exchange);

	OK();

done:
	END();
}

int
reject_follow (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *follow_id;

	req->status = 403;
	kore_buf_reset(response);

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);


/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (1)
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' AND status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' AND status='pending'",
				follow_id,
				id
		);

	}

	RUN_QUERY (query,"could not run select query on follow");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("follow-id is not valid");

	// NOTE: follow_id is primary key 
	CREATE_STRING (query,
			"UPDATE follow SET status='rejected' WHERE follow_id = '%s'",
				follow_id
	);
	RUN_QUERY (query,"could not run update query on follow");

	OK();

done:
	END();
}

int
get_follow_status (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

//////////////////////////////////////////////////

	if (1)
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,topic,validity,status "
			"FROM follow "
			"WHERE from_id LIKE '%s/%%' "
			"ORDER BY time DESC",
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,topic,validity,status "
			"FROM follow "
			"WHERE from_id = '%s' "
			"ORDER BY time DESC",
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"follow-id\":\"%s\","
			"\"from\":\"%s\","
			"\"to\":\"%s\","
			"\"time\":\"%s\","
			"\"topic\":\"%s\","
			"\"validity\":\"%s\","
			"\"status\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5),
			kore_pgsql_getvalue(&sql,i,6)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]\n",2);

	OK();

done:
	END();
}

int
get_follow_requests (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (1)
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,topic,validity "
			"FROM follow "
			"WHERE exchange LIKE '%s/%%.%%' AND status='pending' "
			"ORDER BY time",
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,topic,validity "
			"FROM follow "
			"WHERE exchange LIKE '%s.%%' AND status='pending' "
			"ORDER BY time",
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"follow-id\":\"%s\","
			"\"from\":\"%s\","
			"\"to\":\"%s\","
			"\"time\":\"%s\","
			"\"topic\":\"%s\","
			"\"validity\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]\n",2);

	OK();

done:
	END();
}

int
permissions (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *entity;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	)

	if (1)
	{
		if (! http_request_header(req, "entity", &entity))
			BAD_REQUEST("entity value not specified in header");
			
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of entity");
	}
	else
	{
		entity = id;
	}

/////////////////////////////////////////////////

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT exchange FROM acl WHERE from_id='%s' "
			"AND valid_till > NOW()",entity
	);
	RUN_QUERY (query,"could not query acl table");

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	int num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
				response,
					"\"%s\",",
						kore_pgsql_getvalue(&sql,i,0)
		);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"]\n",2);

	OK();

done:
	END();

}
