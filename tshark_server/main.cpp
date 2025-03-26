#include "analysis.h"
#include "mutils.h"
#include "oatpp/core/async/Coroutine.hpp"
#include "oatpp/encoding/Base64.hpp"
#include "oatpp/parser/json/mapping/Serializer.hpp"
#include "rapidjson/allocators.h"
#include "rapidjson/document.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
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
#include <sys/types.h>
#include <unordered_map>

const uint32_t THREAD_COUNT = 1;
TSharkManager m;

namespace oatpp {
    namespace __class {

        struct RawString : std::string {
            public:
            static const ClassId CLASS_ID;

            static Type *getType() {
                static Type type(CLASS_ID);
                return &type;
            }

            static void SerializerMethod(
                oatpp::parser::json::mapping::Serializer *,
                data::stream::ConsistentOutputStream *stream,
                const oatpp::Void &polymorph) {
                if (polymorph) {
                    std::string *t = static_cast<RawString *>(polymorph.get());
                    if (!t->empty())
                        stream->writeSimple(t->data(), t->size());
                    else
                        stream->writeSimple("null", 4);
                }
                else {
                    stream->writeSimple("null", 4);
                }
            }
        };
    }
    const ClassId __class::RawString::CLASS_ID("RAWSTR");

}
struct RawStringWrapper
    : oatpp::ObjectWrapper<std::string, oatpp::__class::RawString> {
    RawStringWrapper() {}
    operator std::string() const {
        if (this->m_ptr == nullptr) {
            throw std::runtime_error("[oatpp::data::mapping::type::String::"
                                     "operator std::string() const]: "
                                     "Error. Null pointer.");
        }
        return this->m_ptr.operator*();
    }
    inline RawStringWrapper &operator=(std::shared_ptr<std::string> str) {
        m_ptr = str;
        return *this;
    }
};

#include OATPP_CODEGEN_BEGIN(DTO)

class DTO_Base : public oatpp::DTO {
    DTO_INIT(DTO_Base, DTO);
    enum Code {
        SUCCESS = 200,
        RUNNING = 201,
        FAILURE = 400,
    };
    DTO_FIELD(UInt16, code, "code");
    DTO_FIELD(String, msg, "msg");
};

class DTO_Data : public DTO_Base {
    DTO_INIT(DTO_Data, DTO_Base);
    DTO_FIELD(UInt32, size, "size") = 0u;
    DTO_FIELD(RawStringWrapper, data, "data");
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
            auto ifaces = infos.get();
            auto ret = DTO_Data::createShared();
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            ret->size = ifaces.size();
            rapidjson::Value list;
            rapidjson::MemoryPoolAllocator<> alloc;
            list.SetArray();
            for (auto const &i : ifaces) {
                list.PushBack(i.to_json_obj(alloc), alloc);
            }
            ret->data = std::make_shared<std::string>(utils_to_json(list));
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
            auto ret = DTO_Base::createShared();
            if (res.valid()) {
                if (res.get()) {
                    ret->code = DTO_Base::SUCCESS;
                    ret->msg = "启动成功!";
                }
                else {
                    ret->code = DTO_Base::FAILURE;
                    ret->msg = "启动失败!";
                }
            }
            else if (m.interfaces_activity_monitor_is_running()) {
                ret->code = DTO_Base::RUNNING;
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
            auto ret = DTO_Base::createShared();
            if (!res.valid()) res = m.interfaces_activity_monitor_stop();
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.get()) {
                ret->code = DTO_Base::SUCCESS;
                ret->msg = "停止成功!";
            }
            else {
                ret->code = DTO_Base::FAILURE;
                ret->msg = "停止失败!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/interfaces/monitor/read", interfaces_monitor_read) {
        ENDPOINT_ASYNC_INIT(interfaces_monitor_read);
        Action act() override {
            auto obj = DTO_Data::createShared();
            auto info = m.interfaces_activity_monitor_read();
            rapidjson::MemoryPoolAllocator<> alloc;
            rapidjson::Value data_obj;
            data_obj.SetObject();
            for (auto &i : info) {
                data_obj.AddMember(
                    rapidjson::Value(i.first.c_str(), i.first.size()),
                    rapidjson::Value(i.second), alloc);
            }
            obj->code = obj->SUCCESS;
            obj->msg = "获取成功";
            obj->size = info.size();
            obj->data = std::make_shared<std::string>(utils_to_json(data_obj));
            return _return(
                controller->createDtoResponse(Status::CODE_200, obj));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/start", capture_start) {
        ENDPOINT_ASYNC_INIT(capture_start);
        std::future<bool> res;
        Action act() override {
            std::string ifname =
                utils_url_decode(request->getQueryParameter("if", ""));
            auto ret = DTO_Base::createShared();
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
                    ret->code = DTO_Base::SUCCESS;
                    ret->msg = "启动成功!";
                }
                else {
                    ret->code = DTO_Base::FAILURE;
                    ret->msg = "启动失败!";
                }
            }
            else if (m.capture_is_running()) {
                ret->code = DTO_Base::RUNNING;
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
            using namespace std::chrono_literals;
            std::string path =
                utils_url_decode(request->getQueryParameter("path"));
            auto ret = DTO_Base::createShared();
            if (!res.valid()) res = m.capture_from_file(path);
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return waitRepeat(100ms);
                }
            }
            if (res.get()) {
                ret->code = DTO_Base::SUCCESS;
                ret->msg = "加载完成!";
            }
            else {
                ret->code = DTO_Base::FAILURE;
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
            auto ret = DTO_Base::createShared();
            if (!res.valid()) res = m.capture_stop();
            if (res.valid()) {
                std::future_status stat = res.wait_for(std::chrono::seconds(0));
                if (stat == std::future_status::timeout) {
                    return repeat();
                }
            }
            if (res.get()) {
                ret->code = DTO_Base::SUCCESS;
                ret->msg = "停止成功!";
            }
            else {
                ret->code = DTO_Base::FAILURE;
                ret->msg = "停止失败!";
            }
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/packet/brief", capture_packet_brief) {
        ENDPOINT_ASYNC_INIT(capture_packet_brief);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            std::unordered_map<std::string, std::string> params;
            std::unique_ptr<std::vector<std::shared_ptr<Packet>>> data;
            try {
                for (auto &i : request->getQueryParameters().getAll()) {
                    params[utils_url_decode(i.first.std_str())] =
                        utils_url_decode(i.second.std_str());
                }
                data = m.capture_get_brief(params);
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            rapidjson::Value data_obj;
            rapidjson::MemoryPoolAllocator<> alloc;
            data_obj.SetArray();
            for (auto &i : *data) {
                data_obj.PushBack(i->to_json_obj(alloc), alloc);
            }
            ret->size = data->size();
            ret->data = std::make_shared<std::string>(utils_to_json(data_obj));
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/packet/total", capture_get_total) {
        ENDPOINT_ASYNC_INIT(capture_get_total);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            try {
                ret->size = m.capture_get_brief_total();
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/packet/raw", capture_packet_raw) {
        ENDPOINT_ASYNC_INIT(capture_packet_raw);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            ret->msg = "获取失败";
            uint32_t idx = 0;
            try {
                idx = std::stoul(
                    utils_url_decode(request->getQueryParameter("idx")));
                auto data = m.capture_get_raw(idx);
                ret->size = data->size();
                ret->data = std::make_shared<std::string>(
                    "\"" +
                    oatpp::encoding::Base64::encode(
                        data->data(), data->size()) +
                    "\"");
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            return _return(
                controller->createDtoResponse(Status::CODE_200, ret));
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/packet/detail", capture_packet_detail) {
        ENDPOINT_ASYNC_INIT(capture_packet_detail);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            uint32_t pos;
            try {
                pos = std::stoul(request->getQueryParameter("idx", ""));
                ret->data =
                    std::make_shared<std::string>(m.capture_get_detail(pos));
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            if (!ret->data->empty()) {
                ret->code = ret->SUCCESS;
                ret->msg = "获取成功";
                ret->size = 1;
            }
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/capture/sessions", capture_sessions) {
        ENDPOINT_ASYNC_INIT(capture_sessions);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            ret->msg = "获取失败";
            std::unordered_map<std::string, std::string> params;
            try {
                for (auto &i : request->getQueryParameters().getAll()) {
                    params[utils_url_decode(i.first.std_str())] =
                        utils_url_decode(i.second.std_str());
                }
                auto sessions = m.capture_get_sessions(params);
                rapidjson::Value data_obj;
                rapidjson::MemoryPoolAllocator<> alloc;
                data_obj.SetArray();
                for (auto &i : *sessions) {
                    data_obj.PushBack(i->to_json_obj(alloc), alloc);
                }
                ret->data =
                    std::make_shared<std::string>(utils_to_json(data_obj));
                ret->size = sessions->size();
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/statistic/ip", statistic_ip) {
        ENDPOINT_ASYNC_INIT(statistic_ip);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            ret->msg = "获取失败";
            try {
                Analyzer::IpStatistic stat(*m.capture_get_sessions({}));
                ret->size = stat.infos.size();
                ret->data = std::make_shared<std::string>(stat.to_json());
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/statistic/proto", statistic_proto) {
        ENDPOINT_ASYNC_INIT(statistic_proto);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            ret->msg = "获取失败";
            try {
                Analyzer::ProtoStatistic stat(*m.capture_get_sessions({}));
                ret->size = stat.infos.size();
                ret->data = std::make_shared<std::string>(stat.to_json());
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
            return _return(res);
        }
    };

    ENDPOINT_ASYNC("GET", "/statistic/country", statistic_country) {
        ENDPOINT_ASYNC_INIT(statistic_country);
        Action act() override {
            auto ret = DTO_Data::createShared();
            ret->code = ret->FAILURE;
            ret->msg = "获取失败";
            try {
                Analyzer::CountryStatistic stat(*m.capture_get_sessions({}));
                ret->size = stat.infos.size();
                ret->data = std::make_shared<std::string>(stat.to_json());
            }
            catch (std::exception &e) {
                ret->msg = e.what();
                return _return(
                    controller->createDtoResponse(Status::CODE_400, ret));
            }
            ret->code = ret->SUCCESS;
            ret->msg = "获取成功";
            auto res = controller->createDtoResponse(Status::CODE_200, ret);
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
            {"127.0.0.1", 8080});
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
        json->getSerializer()->setSerializerMethod(
            oatpp::__class::RawString::CLASS_ID,
            oatpp::__class::RawString::SerializerMethod);
        return json;
    }());
};

void interrupt(int sig) {
    LOG_F(WARNING, "Interrupt by Ctrl+C.");
    exit(sig);
}

int main(int argc, char **argv) {
    loguru::g_stderr_verbosity = 0; // 0 (INFO) by default.
    loguru::g_colorlogtostderr =
        true; // If you don't want color in your terminal.
    loguru::g_flush_interval_ms = 0; // Unbuffered (0) by default.
    loguru::g_preamble_header =
        true; // Prepend each log start by a descriptions line with all columns
              // name?
    loguru::g_preamble = true; // Prefix each log line with date, time etc?

    // Turn off individual parts of the preamble
    loguru::g_preamble_date = false;  // The date field
    loguru::g_preamble_time = false;  // The time of the current day
    loguru::g_preamble_uptime = true; // The time since init call
    loguru::g_preamble_thread = true; // The logging thread
    loguru::g_preamble_file =
        true; // The file from which the log originates from
    loguru::g_preamble_verbose = true; // The verbosity field
    loguru::g_preamble_pipe = true; // The pipe symbol right before the message
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