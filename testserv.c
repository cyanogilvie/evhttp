#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include "evhttp.h"

int	running = 1;

void got_msg(struct evhttp_con* con)
{
	evhttp_err	err = {NULL, EVHTTP_OK};
	size_t		body_len = evhttp_con_get_body_len(con);

	printf("Got message\n");

	if (evhttp_con_target_match(con, "/server/state")) {
		switch (evhttp_con_get_method(con)) {
			case EVHTTP_METHOD_GET:
				EVHTTP_CHECK(finally, err, evhttp_con_set_body(con, running ? "running" : "stopping"));
				break;

			case EVHTTP_METHOD_PUT:
				if (body_len == 4 && memcmp("stop", evhttp_con_get_body(con), body_len) == 0) {
					running = 0;
					EVHTTP_CHECK(finally, err, evhttp_con_set_body(con, "Stopping"));
				} else {
					EVHTTP_CHECK(finally, err, evhttp_con_set_status(con, 400, "Invalid state"));
					EVHTTP_CHECK(finally, err, evhttp_con_set_body(con, "Invalid state"));
				}
				break;

			default:
				EVHTTP_CHECK(finally, err, evhttp_con_set_status(con, 405));
				EVHTTP_CHECK(finally, err, evhttp_con_set_body(con, "Only GET and PUT allowed to /server/state"));
		}
	} else {
		EVHTTP_CHECK(finally, err, evhttp_con_set_status(con, 404));
		EVHTTP_CHECK(finally, err, evhttp_con_set_body(con, "No such resource"));
	}

finally:
	if (err.msg) {
		evhttp_con_set_status(con, 500);
		evhttp_con_set_body(con, err.msg);	// Not safe - could leak privileged info to untrusted parties.  Here for demonstration purposes only.
	}
	err = evhttp_con_respond(con);
	if (err.msg) {
		fprintf(stderr, "Respond error: %s\n", err.msg);
	}
}


int main(int argc, const char** argv)
{
	struct evhttp*	http = NULL;
	evhttp_err		err = {NULL, EVHTTP_OK};
	fd_set			rfds;
	int				rc;
	int				http_fd;

	EVHTTP_CHECK(finally, err, evhttp_server(got_msg, &http));
	EVHTTP_CHECK(finally, err, evhttp_server_listen(http, "0.0.0.0", "1234"));
	EVHTTP_CHECK(finally, err, evhttp_server_listen(http, "::1", "1234"));

	http_fd = evhttp_fd(http);

	while (running) {
		FD_ZERO(&rfds);
		FD_SET(http_fd, &rfds);

resume:
		rc = select(http_fd+1, &rfds, NULL, NULL, NULL);
		if (-1 == rc) {
			if (errno == EINTR) goto resume;
			perror("select");
		}

		if (FD_ISSET(http_fd, &rfds))
			evhttp_handle_events(http);
	}

finally:
	evhttp_close(&http);

	if (err.msg) {
		fprintf(stderr, "evhttp error: %s\n", err.msg);
		return 1;
	}

	return 0;
}

