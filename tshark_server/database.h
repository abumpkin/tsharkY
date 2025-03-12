/**
 * @file database.h
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
#include "SQLiteCpp/Database.h"
#include "SQLiteCpp/Statement.h"
#include "SQLiteCpp/Transaction.h"
#include "fmt/format.h"
#include "mutils.h"
#include "tshark_info.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <cstdint>
#include <exception>
#include <fmt/core.h>
#include <loguru.hpp>
#include <memory>
#include <string>
#include <vector>

struct TsharkDB {
    std::unique_ptr<SQLite::Database> db;

    private:
    TsharkDB(std::string const &path) {
        if (!utils_test_valid_filename(path).empty()) {
            try {
                db = std::make_unique<SQLite::Database>(
                    path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
        }
    }

    public:
    static std::shared_ptr<TsharkDB> connect(std::string const &path) {
        return std::make_shared<TsharkDB>(TsharkDB(path));
    }
};

struct DBBriefTable {
    std::shared_ptr<TsharkDB> con;
    static constexpr const char name[] = "brief_table";

    private:
    std::shared_ptr<SQLite::Transaction> transaction;
    std::unique_ptr<SQLite::Statement> stat_insert;
    std::unique_ptr<SQLite::Statement> stat_delete;
    std::unique_ptr<SQLite::Statement> stat_select;

    int exec(std::string const &sql) {
        try {
            return con->db->exec(sql);
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    public:
    DBBriefTable(std::shared_ptr<TsharkDB> const &con) : con{con} {
        check_table();
        std::string sql = R"(
        INSERT OR REPLACE INTO {} VALUES (
            @idx,
            @frame_timestamp,
            @frame_protocol,
            @frame_info,
            @src_location,
            @dst_location,
            @src_mac,
            @dst_mac,
            @src_ip,
            @dst_ip,
            @src_port,
            @dst_port,
            @cap_off,
            @cap_len,
            @data
        ))";
        sql = fmt::format(sql, name);
        stat_insert = std::make_unique<SQLite::Statement>(*con->db, sql);
        sql = R"(
        DELETE FROM {} WHERE idx = ?
        )";
        sql = fmt::format(sql, name);
        stat_delete = std::make_unique<SQLite::Statement>(*con->db, sql);
        sql = R"(
        SELECT * FROM {} WHERE idx >= @idx ORDER BY idx ASC LIMIT @size
        )";
        sql = fmt::format(sql, name);
        stat_select = std::make_unique<SQLite::Statement>(*con->db, sql);
    }

    int clear() {
        std::string sql = R"(
        DROP TABLE IF EXISTS {};
        )";
        sql = fmt::format(sql, name);
        exec(sql);
        return check_table();
    }

    int check_table() {
        std::string sql = R"(
        CREATE TABLE IF NOT EXISTS {} (
            idx INTEGER PRIMARY KEY ON CONFLICT REPLACE,
            frame_timestamp NUMERIC DEFAULT 0,
            frame_protocol TEXT,
            frame_info TEXT,
            src_location TEXT,
            dst_location TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            cap_off INTEGER,
            cap_len INTEGER,
            data BLOB
        ))";
        sql = fmt::format(sql, name);
        return exec(sql);
    }

    bool commit_transaction() {
        try {
            if (transaction) {
                transaction->commit();
                transaction.reset();
                return true;
            }
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return false;
    }

    bool has_transaction() const {
        return transaction != nullptr;
    }

    bool start_transaction() {
        if (has_transaction()) return false;
        try {
            transaction = std::make_shared<SQLite::Transaction>(*con->db);
            if (transaction) return true;
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return false;
    }

    int insert(std::shared_ptr<Packet> p) {
        if (!stat_insert) return 0;
        try {
            stat_insert->reset();
            stat_insert->bind("@idx", p->idx);
            stat_insert->bind("@frame_timestamp", p->frame_timestamp);
            stat_insert->bind("@frame_protocol", p->frame_protocol);
            stat_insert->bind("@frame_info", p->frame_info);
            stat_insert->bind("@src_location", p->src_location);
            stat_insert->bind("@dst_location", p->dst_location);
            stat_insert->bind("@src_mac", p->src_mac);
            stat_insert->bind("@dst_mac", p->dst_mac);
            stat_insert->bind("@src_ip", p->src_ip);
            stat_insert->bind("@dst_ip", p->dst_ip);
            stat_insert->bind("@src_port", p->src_port);
            stat_insert->bind("@dst_port", p->dst_port);
            stat_insert->bind("@cap_off", p->cap_off);
            stat_insert->bind("@cap_len", p->cap_len);
            if (p->data)
                stat_insert->bindNoCopy(
                    "@data", p->data->data(), p->data->size());
            return stat_insert->exec();
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    int delete_one(uint32_t idx) {
        if (!stat_delete) return 0;
        try {
            stat_delete->reset();
            stat_delete->bind(1, idx);
            return stat_insert->exec();
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    std::vector<std::shared_ptr<Packet>> select(uint32_t idx, uint32_t size) {
        std::vector<std::shared_ptr<Packet>> ret;
        if (!stat_select) return ret;
        try {
            stat_select->reset();
            stat_select->bind("@idx", idx);
            stat_select->bind("@size", size);
            while (stat_select->executeStep()) {
                std::shared_ptr<Packet> p = std::make_shared<Packet>();
                p->idx = stat_select->getColumn("idx").getUInt();
                p->frame_timestamp =
                    stat_select->getColumn("frame_timestamp").getString();
                p->frame_protocol =
                    stat_select->getColumn("frame_protocol").getString();
                p->frame_info =
                    stat_select->getColumn("frame_info").getString();
                p->src_location =
                    stat_select->getColumn("src_location").getString();
                p->dst_location =
                    stat_select->getColumn("dst_location").getString();
                p->src_mac = stat_select->getColumn("src_mac").getString();
                p->dst_mac = stat_select->getColumn("dst_mac").getString();
                p->src_ip = stat_select->getColumn("src_ip").getString();
                p->dst_ip = stat_select->getColumn("dst_ip").getString();
                p->src_port = stat_select->getColumn("src_port").getUInt();
                p->dst_port = stat_select->getColumn("dst_port").getUInt();
                p->cap_off = stat_select->getColumn("cap_off").getUInt();
                p->cap_len = stat_select->getColumn("cap_len").getUInt();
                auto data_col = stat_select->getColumn("data");
                p->data = std::make_shared<std::vector<char>>(
                    static_cast<const char *>(data_col.getBlob()),
                    static_cast<const char *>(data_col.getBlob()) +
                        data_col.getBytes());
                ret.push_back(p);
            }
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return ret;
    }
};