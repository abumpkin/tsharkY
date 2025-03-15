
#include "analysis.h"
#include "mutils.h"
#include "parser_stream.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include "unistream.h"
#include <memory>

int main() {
    SharkCaptureThread t;
    std::shared_ptr<ParserStreamPacket> ps = std::make_shared<ParserStreamPacket>();
    t.start_capture({ps});
    return 0;
}