#include "mutils.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include <chrono>
#include <csignal>
#include <cstdint>
#include <future>
#include <loguru.hpp>
#include <memory>
#include <oatpp/core/Types.hpp>
#include <oatpp/core/base/Environment.hpp>
#include <oatpp/core/data/mapping/type/Object.hpp>
#include <oatpp/core/macro/codegen.hpp>
#include <oatpp/core/macro/component.hpp>
#include <oatpp/core/utils/ConversionUtils.hpp>
#include <oatpp/core/utils/String.hpp>
#include <oatpp/encoding/Unicode.hpp>
#include <oatpp/network/Address.hpp>
#include <oatpp/network/ConnectionProvider.hpp>
#include <oatpp/network/Server.hpp>
#include <oatpp/network/tcp/server/ConnectionProvider.hpp>
#include <oatpp/parser/json/Utils.hpp>
#include <oatpp/parser/json/mapping/ObjectMapper.hpp>
#include <oatpp/web/server/AsyncHttpConnectionHandler.hpp>
#include <oatpp/web/server/HttpConnectionHandler.hpp>
#include <oatpp/web/server/api/ApiController.hpp>
#include <oatpp/web/server/interceptor/RequestInterceptor.hpp>
#include <oatpp/web/server/interceptor/ResponseInterceptor.hpp>
#include <string>

const uint32_t THREAD_COUNT = 1;
TSharkManager m;

#include OATPP_CODEGEN_BEGIN(DTO)

class DTO_Status : public oatpp::DTO {
    DTO_INIT(DTO_Status, DTO);
    enum Code {
        SUCCESS = 200,
        RUNNING = 201,
        FAILURE = 400,
    };
    DTO_FIELD(UInt16, code, "code");
    DTO_FIELD(String, msg, "msg");
};

class DTO_IfaceInfo : public oatpp::DTO {
    DTO_INIT(DTO_IfaceInfo, DTO);
    DTO_FIELD(oatpp::String, name, "name");
    DTO_FIELD(oatpp::String, friendly_name, "friendly_name");
    DTO_FIELD(oatpp::Vector<oatpp::String>, addrs, "addrs");
    DTO_FIELD(oatpp::String, type, "type");
};

class DTO_IfaceInfos : public oatpp::DTO {
    DTO_INIT(DTO_IfaceInfos, DTO);
    DTO_FIELD(Vector<Object<DTO_IfaceInfo>>, iface);
};

#include OATPP_CODEGEN_END(DTO)

#include OATPP_CODEGEN_BEGIN(ApiController) ////
struct Controller : public oatpp::web::server::api::ApiController {
    Controller(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, obj_map))
        : oatpp::web::server::api::ApiController(obj_map) {}

    ENDPOINT_ASYNC("GET", "/interfaces", interfaces) {
        ENDPOINT_ASYNC_INIT(interfaces);
        std::future<std::vector<IfaceInfo>> infos;
        Action act() override {
            if (!infos.valid()) infos = m.interfaces_get_info();
            if (infos.valid()) {
                std::future_status stat =
                    infos.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            auto ret = DTO_IfaceInfos::createShared();
            ret->iface = {};
            for (auto const &i : infos.get()) {
                auto t = DTO_IfaceInfo::createShared();
                t->name = i.name;
                t->friendly_name = i.friendly_name;
                t->type = InterfaceTypeToString(i.type);
                t->addrs = {};
                t->addrs->assign(i.addrs.begin(), i.addrs.end());
                ret->iface->push_back(t);
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC(
        "GET", "/interfaces/monitor/start", interfaces_monitor_start) {
        ENDPOINT_ASYNC_INIT(interfaces_monitor_start);
        std::future<bool> res;
        Action act() override {
            if (!res.valid() && !m.interfaces_activity_monitor_is_running())
                res = m.interfaces_activity_monitor_start();
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            auto ret = DTO_Status::createShared();
            if (res.valid()) {
                if (res.get()) {
                    ret->code = DTO_Status::SUCCESS;
                    ret->msg = "启动成功!";
                }
                else {
                    ret->code = DTO_Status::FAILURE;
                    ret->msg = "启动失败!";
                }
            }
            else if (m.interfaces_activity_monitor_is_running()) {
                ret->code = DTO_Status::RUNNING;
                ret->msg = "网络活动监视中!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/interfaces/monitor/stop", interfaces_monitor_stop) {
        ENDPOINT_ASYNC_INIT(interfaces_monitor_stop);
        std::future<bool> res;
        Action act() override {
            auto ret = DTO_Status::createShared();
            if (!res.valid()) res = m.interfaces_activity_monitor_stop();
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.get()) {
                ret->code = DTO_Status::SUCCESS;
                ret->msg = "停止成功!";
            }
            else {
                ret->code = DTO_Status::FAILURE;
                ret->msg = "停止失败!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/interfaces/monitor/read", interfaces_monitor_read) {
        ENDPOINT_ASYNC_INIT(interfaces_monitor_read);
        Action act() override {
            auto obj = oatpp::UnorderedFields<oatpp::UInt32>::createShared();
            for (auto &i : m.interfaces_activity_monitor_read()) {
                obj->insert(i);
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, obj));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/start", capture_start) {
        ENDPOINT_ASYNC_INIT(capture_start);
        std::future<bool> res;
        Action act() override {
            std::string ifname = request->getQueryParameter("if", "");
            auto ret = DTO_Status::createShared();
            if (!res.valid() && !m.capture_is_running())
                res = m.capture_start(ifname);
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.valid()) {
                if (res.get()) {
                    ret->code = DTO_Status::SUCCESS;
                    ret->msg = "启动成功!";
                }
                else {
                    ret->code = DTO_Status::FAILURE;
                    ret->msg = "启动失败!";
                }
            }
            else if (m.capture_is_running()) {
                ret->code = DTO_Status::RUNNING;
                ret->msg = "捕获运行中!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/load_file", capture_load_file) {
        ENDPOINT_ASYNC_INIT(capture_load_file);
        std::future<bool> res;
        Action act() override {
            std::string path =
                utils_url_decode(request->getQueryParameter("path"));
            auto ret = DTO_Status::createShared();
            if (!res.valid()) res = m.capture_from_file(path);
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.get()) {
                ret->code = DTO_Status::SUCCESS;
                ret->msg = "加载完成!";
            }
            else {
                ret->code = DTO_Status::FAILURE;
                ret->msg = "加载失败!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/stop", capture_stop) {
        ENDPOINT_ASYNC_INIT(capture_stop);
        std::future<bool> res;
        Action act() override {
            auto ret = DTO_Status::createShared();
            if (!res.valid()) res = m.capture_stop();
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.get()) {
                ret->code = DTO_Status::SUCCESS;
                ret->msg = "停止成功!";
            }
            else {
                ret->code = DTO_Status::FAILURE;
                ret->msg = "停止失败!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/get/brief", capture_get_brief) {
        ENDPOINT_ASYNC_INIT(capture_get_brief);
        Action act() override {
            uint32_t pos, len;
            try {
                pos = std::stoul(request->getQueryParameter("pos", "0"));
                len = oatpp::utils::conversion::strToUInt32(
                    request->getQueryParameter("len", "0")->c_str());
            }
            catch (...) {
                return _return(controller->createResponse(Status::CODE_400));
            }

            std::string ret = m.capture_get_brief(pos, len);
            auto res = controller->createResponse(Status::CODE_200, ret);
            res->putHeader("Content-Type", "application/json");
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/get/detail", capture_get_detail) {
        ENDPOINT_ASYNC_INIT(capture_get_detail);
        Action act() override {
            uint32_t pos;
            try {
                pos = std::stoul(request->getQueryParameter("idx", ""));
            }
            catch (...) {
                return _return(controller->createResponse(Status::CODE_400));
            }

            std::string ret = m.capture_get_detail(pos);
            auto res = controller->createResponse(Status::CODE_200, ret);
            res->putHeader("Content-Type", "application/json");
            return _return(res);
        }
    };
};

#include OATPP_CODEGEN_END(ApiController) /////

struct RequestInformation
    : oatpp::web::server::interceptor::RequestInterceptor {
    virtual std::shared_ptr<OutgoingResponse> intercept(
        const std::shared_ptr<IncomingRequest> &request) {
        if (request)
            LOG_F(INFO, "IN: %s - %s",
                request->getStartingLine().method.std_str().c_str(),
                request->getStartingLine().path.std_str().c_str());
        return nullptr;
    }
};

struct ResponseInformation
    : oatpp::web::server::interceptor::ResponseInterceptor {
    virtual std::shared_ptr<OutgoingResponse> intercept(
        const std::shared_ptr<IncomingRequest> &request,
        const std::shared_ptr<OutgoingResponse> &response) {
        if (request && response)
            LOG_F(INFO, "OUT: %s - %s\t\t%d (%s)",
                request->getStartingLine().method.std_str().c_str(),
                request->getStartingLine().path.std_str().c_str(),
                response->getStatus().code, response->getStatus().description);
        return response;
    }
};

class AppComponent {
    public:
    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::network::ServerConnectionProvider>,
        connection_provider)([] {
        return oatpp::network::tcp::server::ConnectionProvider::createShared(
            {"localhost", 8000, oatpp::network::Address::IP_4});
    }());
    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::web::server::HttpRouter>, httpRouter)([] {
        return oatpp::web::server::HttpRouter::createShared();
    }());
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ConnectionHandler>,
        serverConnectionHandler)([] {
        OATPP_COMPONENT(
            std::shared_ptr<oatpp::web::server::HttpRouter>, router);
        auto handler =
            oatpp::web::server::AsyncHttpConnectionHandler::createShared(
                router, THREAD_COUNT);
        handler->addResponseInterceptor(
            std::make_shared<ResponseInformation>());
        handler->addRequestInterceptor(std::make_shared<RequestInformation>());
        return handler;
    }());
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::data::mapping::ObjectMapper>,
        apiObjectMapper)([] {
        auto json = oatpp::parser::json::mapping::ObjectMapper::createShared();
        json->getSerializer()->getConfig()->useBeautifier = true;
        return json;
    }());
};

void interrupt(int sig) {
    LOG_F(WARNING, "Interrupt by Ctrl+C.");
    exit(sig);
}

int main(int argc, char **argv) {
    loguru::init(argc, argv);
    signal(SIGINT, interrupt);
    //  loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);

    oatpp::base::Environment::init();
    AppComponent components;
    OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);

    auto myController = std::make_shared<Controller>();
    router->addController(myController);

    OATPP_COMPONENT(
        std::shared_ptr<oatpp::network::ConnectionHandler>, connectionHandler);

    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>,
        connectionProvider);

    oatpp::network::Server server(connectionProvider, connectionHandler);

    LOG_F(INFO, "Server running on port %s",
        (char *)connectionProvider->getProperty("port").getData());

    router->logRouterMappings();
    server.run();

    oatpp::base::Environment::destroy();
    return 0;
}