/*!rules:re2c:common
	re2c:api:style					= free-form;
*/

/*!rules:re2c:basic
	!use:common;
	re2c:eof				= -1;
	re2c:flags:tags			= 1;
	re2c:yyfill:check		= 0;
	re2c:define:YYCTYPE		= "unsigned char";
	re2c:define:YYCURSOR	= "s";
	re2c:define:YYGETSTATE	= "-1";
	re2c:define:YYSETSTATE	= "";
	re2c:define:YYMARKER	= "mar";
	re2c:define:YYFILL		= "";
	re2c:tags:expression	= "@@";

	end			= "\x00";
*/

/*!rules:re2c:http_common
	crlf		= '\r'? '\n';		// RFC7230 3.5
	sp			= ' ';
	htab		= '\t';
	ows			= (sp | htab)*;
	rws			= (sp | htab)+;
	digit		= [0-9];
	alpha		= [a-zA-Z];
	hexdigit	= [0-9a-fA-F];
	unreserved	= alpha | digit | [-._~];
	pct_encoded	= "%" hexdigit{2};
	sub_delims	= [!$&'()*+,;=];
	pchar		= unreserved | pct_encoded | sub_delims | [:@];
	vchar		= [\x1f-\x7e];
	tchar		= [-!#$%&'*+.^_`|~] | digit | alpha;

	obs_fold				= #f1 crlf (sp | htab)+ #f2;
	obs_text				= [\x80-\xff];
	field_name				= tchar+;
	field_vchar				= vchar | obs_text;
	field_content			= field_vchar ((sp | htab)+ field_vchar)?;
	field_value				= field_content*;
	field_value_folded		= (field_content* obs_fold field_content*)+;
	header_field			= @h1 field_name @h2 ':' ows @h3 field_value @h4 ows;
	header_field_folded		= @h1 field_name @h2 ':' ows @h3 field_value_folded @h4 ows;
	scheme					= alpha (alpha | digit | [-+.])*;
	userinfo				= (unreserved | pct_encoded | sub_delims | ':')*;
	dec_octet
		= digit
		| [\x31-\x39] digit
		| "1" digit{2}
		| "2" [\x30-\x34] digit
		| "25" [\x30-\x35];
	ipv4address		= dec_octet '.' dec_octet '.' dec_octet '.' dec_octet;
	h16				= hexdigit{1,4};
	ls32			= h16 ':' h16 | ipv4address;
	ipv6address
		=                            (h16 ':'){6} ls32
		|                       '::' (h16 ':'){5} ls32
		| (               h16)? '::' (h16 ':'){4} ls32
		| ((h16 ':'){0,1} h16)? '::' (h16 ':'){3} ls32
		| ((h16 ':'){0,2} h16)? '::' (h16 ':'){2} ls32
		| ((h16 ':'){0,3} h16)? '::'  h16 ':'     ls32
		| ((h16 ':'){0,4} h16)? '::'              ls32
		| ((h16 ':'){0,5} h16)? '::'              h16
		| ((h16 ':'){0,6} h16)? '::';
	ipvfuture		= 'v' hexdigit+ '.' (unreserved | sub_delims | ':' )+;
	ip_literal		= '[' ( ipv6address | ipvfuture ) ']';
	reg_name		= (unreserved | pct_encoded | sub_delims)*;
	path_abempty	= ('/' pchar*)*;
	path_absolute	= '/' (pchar+ ('/' pchar*)*)?;
	path_rootless	= pchar+ ('/' pchar*)*;
	path_empty		= '';
	host			= ip_literal | ipv4address | reg_name;
	port			= digit*;
	query			= (pchar | [/?])*;
	absolute_uri	= scheme ':'
		( '//' (userinfo '@')? host (':' port)? path_abempty
		| (path_absolute | path_rootless | path_empty)
		) ('?' query)?;
	authority		= (userinfo '@')? host (':' port )?;
	origin_form		= path_abempty ('?' query )?;
	http_name		= 'HTTP';
	http_version	= http_name '/' digit '.' digit;
	request_target
		= authority
		| absolute_uri
		| origin_form
		| '*';
	method			= tchar+;
	status_code		= digit{3};
	reason_phrase	= (htab | sp | vchar | obs_text)*;
	status_line		= @v1 http_version @v2 sp @st1 status_code sp reason_phrase crlf;
	rank
		= '0' ( '.' digit{0,3} )?
		| '1' ( '.' '0'{0,3}   )?;
	t_ranking			= ows ';' ows "q=" @r1 rank @r2;
	bws					= ows;
	token				= tchar+;
	qdtext
		= htab
		| sp
		| [\x21-\x5B\x5D-\x7E] \ '"'
		| obs_text;
	quoted_pair			= '\\' ( htab | sp | vchar | obs_text );
	quoted_string		= '"' ( qdtext | quoted_pair )* '"';
	transfer_parameter	= token bws '=' bws ( token | quoted_string );
	parameter			= #p1 token #p2 '=' #p3 ( token | quoted_string ) #p4;
	media_type			= @l1 token '/' token @l2 ( ows ';' ows parameter )*;
*/

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
