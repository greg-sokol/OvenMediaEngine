//==============================================================================
//
//  OvenMediaEngine
//
//  Created by Hyunjun Jang
//  Copyright (c) 2018 AirenSoft. All rights reserved.
//
//==============================================================================
#pragma once

#include "http_request.h"
#include "http_response.h"
#include "http_datastructure.h"

#include "interceptors/http_request_interceptors.h"

#include <base/ovsocket/ovsocket.h>
#include <physical_port/physical_port_manager.h>

// 참고 자료
// RFC7230 - Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing (https://tools.ietf.org/html/rfc7230)
// RFC7231 - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content (https://tools.ietf.org/html/rfc7231)
// RFC7232 - Hypertext Transfer Protocol (HTTP/1.1): Conditional Requests (https://tools.ietf.org/html/rfc7232)

class HttpServer : protected PhysicalPortObserver
{
public:
	HttpServer();
	virtual ~HttpServer();

	virtual bool Start(const ov::SocketAddress &address);
	virtual bool Stop();

	bool AddInterceptor(const std::shared_ptr<HttpRequestInterceptor> &interceptor);
	bool RemoveInterceptor(const std::shared_ptr<HttpRequestInterceptor> &interceptor);

	std::shared_ptr<HttpDefaultInterceptor> GetDefaultInterceptor();

	bool Disconnect(const ov::String &id);

protected:
	//--------------------------------------------------------------------
	// Implementation of PhysicalPortObserver
	//--------------------------------------------------------------------
	void OnConnected(ov::Socket *remote) override;
	void OnDataReceived(ov::Socket *remote, const ov::SocketAddress &address, const std::shared_ptr<const ov::Data> &data) override;
	void OnDisconnected(ov::Socket *remote, PhysicalPortDisconnectReason reason, const std::shared_ptr<const ov::Error> &error) override;

	// @return 파싱이 성공적으로 되었다면 true를, 데이터가 더 필요하거나 오류가 발생하였다면 false이 반환됨
	ssize_t TryParseHeader(const ov::SocketAddress &address, const std::shared_ptr<const ov::Data> &data, const std::shared_ptr<HttpRequest> &request, const std::shared_ptr<HttpResponse> &response);

	// HttpServer와 연결된 physical port
	std::shared_ptr<PhysicalPort> _physical_port;

	std::map<ov::Socket *, std::shared_ptr<HttpRequest>> _client_list;

	std::vector<std::shared_ptr<HttpRequestInterceptor>> _interceptor_list;
	std::shared_ptr<HttpRequestInterceptor> _default_interceptor;
};