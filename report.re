#include "evhttpInt.h"

/*!include:re2c "common.re" */

/*!header:re2c:on */
void report(const char* type, const unsigned char* chunk);
/*!header:re2c:off */

void report(const char* type, const unsigned char* chunk) //<<<
{
	const unsigned char*	s = chunk;
	const unsigned char*	tok;

	printf("%s: \"", type);

loop:
	tok = s;
	/*!local:re2c:report
	!use:basic;

	cr			= "\r";
	lf			= "\n";
	tab			= "\t";
	del			= "\x7F";
	C0			= [\x01-\x1F];
	printable	= [\x01-\x7E\x80-\xFF] \ C0;

	end			{ printf("\" (%d bytes)\n", (int)(s-1-chunk));					return; }

	printable+	{ printf("%.*s", (int)(s-tok), tok);	goto loop; }
	cr			{ printf("\\r");						goto loop; }
	lf			{ printf("\\n");						goto loop; }
	tab			{ printf("\\t");						goto loop; }
	.			{ printf("\\x%02x", *(s-1));			goto loop; }

	*			{ fprintf(stderr, "Error attempting to report chunk send\n");	return; }

	*/
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
