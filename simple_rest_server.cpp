/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utility>
#include "workflow/HttpMessage.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/Workflow.h"
#include "workflow/WFFacilities.h"
#include "rest_request_process.h"


using namespace protocol;
using namespace gwecom::network::rest;

void process(WFHttpTask *server_task, rest_request_process *rest_process)
{

	HttpRequest *req = server_task->get_req();
	HttpResponse *resp = server_task->get_resp();
	const char *uri = req->get_request_uri();
	const char *p = uri;
	if(rest_process == nullptr) {
        resp->set_status_code("500");
        resp->append_output_body("rest_server internal error\n");
        return;
    }

    char addrstr[128];
    struct sockaddr_storage addr;
    socklen_t l = sizeof addr;
    unsigned short remote_port = 0;

    int result = server_task->get_peer_addr((struct sockaddr *)&addr, &l);
    if(result == -1){
        strcpy(addrstr, "Unknown");
    }else {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
            inet_ntop(AF_INET, &sin->sin_addr, addrstr, 128);
            remote_port = ntohs(sin->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, 128);
            remote_port = ntohs(sin6->sin6_port);
        } else {
            strcpy(addrstr, "Unknown");
        }
    }

    printf("Remote-peer: %s:%d, Request-URI: %s\n", addrstr, remote_port, uri);

    if(*p == '/')++p;

    const char* api=p;
    while (*p && *p != '/')
        p++;
    std::string fix_api_string(api, p - api);
    if(fix_api_string != "api"){
        rest_process->process_invalid_uri(resp, nullptr);
        return;
    }

    if(*p == '/')++p;
    const char* func = p;
    while (*p && *p != '?')
        p++;

    const
    std::string rest_function(func, p - func);

	const char* request_method = req->get_method();
	const char* request_data = nullptr;
	size_t request_data_len = 0;

	if(!strcasecmp(request_method, "POST")){
        const void *body;
        size_t body_len;

        req->get_parsed_body(&body, &body_len);
        request_data = (const char*)body;
        request_data_len = body_len;
	}else if(!strcasecmp(request_method, "GET")){
	        if(p && *p == '?')
	            ++p;
            request_data = p;
            request_data_len = strlen(request_data);
	}

	if(rest_function == "get_hwid"){
        rest_process->process_get_hwid(resp, nullptr);
	}else if(rest_function == "upload_license"){
	    rest_process->process_upload_license(resp, request_data);
	}else if(rest_function == "upload_hwid"){
        rest_process->process_upload_hwid(resp, request_data);
	}else if(rest_function == "get_license"){
        rest_process->process_get_license(resp, request_data);
	}
	else{
        rest_process->process_invalid_method(resp, nullptr);
	}
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, char *argv[])
{
	if (argc != 2 && argc != 3 && argc != 5)
	{
		fprintf(stderr, "%s <port> [root path] [cert file] [key file]\n",
				argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	unsigned short port = atoi(argv[1]);
	const char *root = (argc >= 3 ? argv[2] : ".");
	rest_request_process rest_process(root);
	auto&& proc = std::bind(process, std::placeholders::_1, &rest_process);
	WFHttpServer server(proc);
	int ret;

	if (argc == 5)
		ret = server.start(port, argv[3], argv[4]);	/* https server */
	else
		ret = server.start(port);

	if (ret == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("start server");
		exit(1);
	}

	return 0;
}

