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
    std::unique_ptr<SQLite::Transaction> transaction;

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
    TsharkDB(TsharkDB &&) = default;
    static std::shared_ptr<TsharkDB> connect(std::string const &path) {
        return std::make_shared<TsharkDB>(TsharkDB(path));
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
            transaction = std::make_unique<SQLite::Transaction>(*db);
            if (transaction) return true;
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return false;
    }

    ~TsharkDB() {
        if (has_transaction()) commit_transaction();
    }
};

struct DBFixed {
    std::shared_ptr<TsharkDB> con;
    static constexpr const char name[] = "fixed";

    private:
    std::shared_ptr<std::vector<char>> fixed;
    std::string format;
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
    DBFixed(std::shared_ptr<TsharkDB> const &con) : con{con} {
        check_table();
        std::string sql = R"(
            INSERT OR REPLACE INTO {} VALUES (
                @format,
                @data
            )
        )";
        sql = fmt::format(sql, name);
        stat_insert = std::make_unique<SQLite::Statement>(*con->db, sql);
        sql = R"(
            DELETE FROM {}
        )";
        sql = fmt::format(sql, name);
        stat_delete = std::make_unique<SQLite::Statement>(*con->db, sql);
        sql = R"(
            SELECT data, format FROM {} LIMIT 1
        )";
        sql = fmt::format(sql, name);
        stat_select = std::make_unique<SQLite::Statement>(*con->db, sql);
    }

    int clear() {
        if (!stat_delete) return 0;
        try {
            stat_delete->reset();
            return stat_delete->exec();
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    int check_table() {
        std::string sql = R"(
            CREATE TABLE IF NOT EXISTS {} (
                format TEXT PRIMARY KEY NOT NULL ON CONFLICT REPLACE,
                data BLOB
            )
        )";
        sql = fmt::format(sql, name);
        return exec(sql);
    }

    int save(std::vector<char> const &data, std::string format) {
        if (!stat_insert) return 0;
        clear();
        fixed.reset();
        try {
            stat_insert->reset();
            stat_insert->bind("@format", format);
            stat_insert->bindNoCopy("@data", data.data(), data.size());
            return stat_insert->exec();
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    std::shared_ptr<std::vector<char>> get_data() {
        if (fixed) return fixed;
        if (!stat_select) return fixed;
        fixed = std::make_shared<std::vector<char>>();
        if (con->has_transaction()) con->commit_transaction();
        try {
            stat_select->reset();
            if (stat_select->executeStep()) {
                format = stat_select->getColumn("format").getString();
                auto data_col = stat_select->getColumn("data");
                fixed->assign(static_cast<const char *>(data_col.getBlob()),
                    static_cast<const char *>(data_col.getBlob()) +
                        data_col.getBytes());
            }
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return fixed;
    }

    std::string get_format() {
        if (!fixed) get_data();
        return format;
    }
};

struct DBBriefTable {
    struct {
        int idx;
        int frame_timestamp;
        int frame_protocol;
        int frame_info;
        int src_location;
        int dst_location;
        int src_mac;
        int dst_mac;
        int src_ip;
        int dst_ip;
        int src_port;
        int dst_port;
        int cap_off;
        int cap_len;
        int data;
    } Field;
    std::shared_ptr<TsharkDB> con;
    static constexpr const char name[] = "brief_table";

    private:
    std::unique_ptr<SQLite::Statement> stat_insert;
    std::unique_ptr<SQLite::Statement> stat_delete;
    std::unique_ptr<SQLite::Statement> stat_select;
    std::unique_ptr<SQLite::Statement> stat_size;

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
            )
        )";
        sql = fmt::format(sql, name);
        stat_insert = std::make_unique<SQLite::Statement>(*con->db, sql);
        Field.idx = stat_insert->getIndex("@idx");
        Field.frame_timestamp = stat_insert->getIndex("@frame_timestamp");
        Field.frame_protocol = stat_insert->getIndex("@frame_protocol");
        Field.frame_info = stat_insert->getIndex("@frame_info");
        Field.src_location = stat_insert->getIndex("@src_location");
        Field.dst_location = stat_insert->getIndex("@dst_location");
        Field.src_mac = stat_insert->getIndex("@src_mac");
        Field.dst_mac = stat_insert->getIndex("@dst_mac");
        Field.src_ip = stat_insert->getIndex("@src_ip");
        Field.dst_ip = stat_insert->getIndex("@dst_ip");
        Field.src_port = stat_insert->getIndex("@src_port");
        Field.dst_port = stat_insert->getIndex("@dst_port");
        Field.cap_off = stat_insert->getIndex("@cap_off");
        Field.cap_len = stat_insert->getIndex("@cap_len");
        Field.data = stat_insert->getIndex("@data");
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
        sql = R"(
            SELECT count(*) from {}
        )";
        sql = fmt::format(sql, name);
        stat_size = std::make_unique<SQLite::Statement>(*con->db, sql);
    }

    uint32_t size() {
        if (!stat_size) return 0;
        stat_size->reset();
        try{
            if (stat_size->executeStep()) {
                return stat_size->getColumn(0).getUInt();
            }
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return 0;
    }

    int clear() {
        std::string sql = R"(
            DROP TABLE IF EXISTS {}
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
            ) WITHOUT ROWID
        )";
        sql = fmt::format(sql, name);
        return exec(sql);
    }

    int insert(std::shared_ptr<Packet> p) {
        if (!stat_insert) return 0;
        try {
            stat_insert->reset();
            stat_insert->bind(Field.idx, p->idx);
            stat_insert->bind(Field.frame_timestamp, p->frame_timestamp);
            stat_insert->bind(Field.frame_protocol, p->frame_protocol);
            stat_insert->bind(Field.frame_info, p->frame_info);
            stat_insert->bind(Field.src_location, p->src_location);
            stat_insert->bind(Field.dst_location, p->dst_location);
            stat_insert->bind(Field.src_mac, p->src_mac);
            stat_insert->bind(Field.dst_mac, p->dst_mac);
            stat_insert->bind(Field.src_ip, p->src_ip);
            stat_insert->bind(Field.dst_ip, p->dst_ip);
            stat_insert->bind(Field.src_port, p->src_port);
            stat_insert->bind(Field.dst_port, p->dst_port);
            stat_insert->bind(Field.cap_off, p->cap_off);
            stat_insert->bind(Field.cap_len, p->cap_len);
            stat_insert->bind(Field.data);
            if (p->data)
                stat_insert->bindNoCopy(
                    Field.data, p->data->data(), p->data->size());
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

    std::vector<std::shared_ptr<Packet>> select(
        uint32_t idx, uint32_t size, DBFixed &dbfixed) {
        std::vector<std::shared_ptr<Packet>> ret;
        if (!stat_select) return ret;
        if (con->has_transaction()) con->commit_transaction();
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
                p->data = std::make_unique<std::vector<char>>(
                    static_cast<const char *>(data_col.getBlob()),
                    static_cast<const char *>(data_col.getBlob()) +
                        data_col.getBytes());
                p->fixed = dbfixed.get_data();
                ret.push_back(p);
            }
        }
        catch (std::exception &e) {
            LOG_F(ERROR, "ERROR: %s", e.what());
        }
        return ret;
    }
};