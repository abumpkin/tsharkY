/**
 * @file analysis.h
 * @author abumpkin (forwardslash@foxmail.com)
 * @link https://github.com/abumpkin/tsharkY @endlink
 *
 * ISC License
 *
 * @copyright Copyright (c) 2025 abumpkin
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once
#include "tshark_info.h"
#include "unistream.h"
#include <memory>
#include <vector>

struct Analyzer {
    static std::unique_ptr<PacketDefineDecode> packet_detail(
        std::shared_ptr<Packet> pkt) {
        std::string cmd = TSHARK_PATH " -Q -l -r - -T pdml";
        UniStreamDualPipeU analyzer{cmd};
        std::unique_ptr<PacketDefineDecode> dec;
        std::shared_ptr<std::vector<char>> fixed = pkt->fixed.lock();
        analyzer.write(fixed->data(), fixed->size());
        analyzer.write(pkt->data.data(), pkt->data.size());
        analyzer.close_write();
        std::string xml = analyzer.read_until_eof();
        auto pos = xml.find("<packet>");
        if (pos != std::string::npos) {
            xml = xml.substr(pos);
        }
        pos = xml.rfind("</packet>");
        if (pos != std::string::npos) {
            xml.resize(pos + 9);
        }
        dec = std::make_unique<PacketDefineDecode>(xml);
        return dec;
    }
};