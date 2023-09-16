#pragma once

/*
 * @demo examples/websocket_server_test.cpp
 */

#include "HttpServer.hpp"
#include "WebSocketChannel.hpp"

#define websocket_server_t      http_server_t
#define websocket_server_run    http_server_run
#define websocket_server_stop   http_server_stop

namespace hv {

struct WebSocketService {
    std::function<void(const WebSocketChannelPtr&, const HttpRequestPtr&)>  onopen;
    std::function<void(const WebSocketChannelPtr&, const std::string&)>     onmessage;
    std::function<void(const WebSocketChannelPtr&)>                         onclose;
    int ping_interval;

    WebSocketService() {
        ping_interval = 0;
        // ping_interval = 10000; // ms
    }
};

class WebSocketServer : public HttpServer {
public:
    void registerWebSocketService(WebSocketService* service) {
        internals::ws = service;
    }
};

}

 // HV_WEBSOCKET_SERVER_H_
