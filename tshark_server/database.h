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
#include "SQLiteCpp/Savepoint.h"
#include "SQLiteCpp/Statement.h"
#include "SQLiteCpp/Transaction.h"
#include "fmt/format.h"
#include "mutils.h"
#include "tshark_info.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fmt/core.h>
#include <loguru.hpp>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct TsharkDB {
    struct ProtectedDB : std::shared_lock<std::shared_mutex> {
        TsharkDB *p;
        ProtectedDB(TsharkDB *p, std::shared_mutex &mt)
            : std::shared_lock<std::shared_mutex>(mt) {
            this->p = p;
        }
        SQLite::Database *operator->() {
            return p->db.get();
        }
        SQLite::Database &operator*() {
            return *p->db;
        }
    };

    struct TableFixed {
        TsharkDB *con;
        static constexpr const char name[] = "fixed";

        private:
        std::shared_ptr<std::vector<char>> fixed;
        std::string format;
        std::unique_ptr<SQLite::Statement> stat_insert;
        std::unique_ptr<SQLite::Statement> stat_delete;
        std::unique_ptr<SQLite::Statement> stat_select;

        int exec(std::string const &sql) {
            TsharkDB::ProtectedDB db = con->get_db();
            try {
                return db->exec(sql);
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        public:
        TableFixed(TsharkDB *con) : con{con} {
            check_table();
            TsharkDB::ProtectedDB db = con->get_db();
            std::string sql = R"(
                INSERT OR REPLACE INTO {} VALUES (
                    @format,
                    @data
                )
            )";
            sql = fmt::format(sql, name);
            stat_insert = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                DELETE FROM {}
            )";
            sql = fmt::format(sql, name);
            stat_delete = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT data, format FROM {} LIMIT 1
            )";
            sql = fmt::format(sql, name);
            stat_select = std::make_unique<SQLite::Statement>(*db, sql);
        }

        int clear() {
            TsharkDB::ProtectedDB db = con->get_db();
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
            TsharkDB::ProtectedDB db = con->get_db();
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
            TsharkDB::ProtectedDB db = con->get_db();
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
            TsharkDB::ProtectedDB db = con->get_db();
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

    struct TableBrief {
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
        TsharkDB *con;
        static constexpr const char name[] = "brief_table";

        private:
        std::unique_ptr<SQLite::Statement> stat_insert;
        std::unique_ptr<SQLite::Statement> stat_delete;
        std::unique_ptr<SQLite::Statement> stat_select_one;
        std::unique_ptr<SQLite::Statement> stat_select;
        std::unique_ptr<SQLite::Statement> stat_size;
        uint32_t total_count;

        int exec(std::string const &sql) {
            TsharkDB::ProtectedDB db = con->get_db();
            try {
                return db->exec(sql);
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        inline std::shared_ptr<Packet> compose_packet(
            SQLite::Statement &stat, TableFixed &dbfixed) {
            std::shared_ptr<Packet> p = std::make_shared<Packet>();
            p->idx = stat.getColumn("idx").getUInt();
            p->frame_timestamp = stat.getColumn("frame_timestamp").getString();
            p->frame_protocol = stat.getColumn("frame_protocol").getString();
            p->frame_info = stat.getColumn("frame_info").getString();
            p->src_location = stat.getColumn("src_location").getString();
            p->dst_location = stat.getColumn("dst_location").getString();
            p->src_mac = stat.getColumn("src_mac").getString();
            p->dst_mac = stat.getColumn("dst_mac").getString();
            p->src_ip = stat.getColumn("src_ip").getString();
            p->dst_ip = stat.getColumn("dst_ip").getString();
            p->src_port = stat.getColumn("src_port").getUInt();
            p->dst_port = stat.getColumn("dst_port").getUInt();
            p->cap_off = stat.getColumn("cap_off").getUInt();
            p->cap_len = stat.getColumn("cap_len").getUInt();
            auto data_col = stat.getColumn("data");
            p->data = std::make_unique<std::vector<char>>(
                static_cast<const char *>(data_col.getBlob()),
                static_cast<const char *>(data_col.getBlob()) +
                    data_col.getBytes());
            p->fixed = dbfixed.get_data();
            return p;
        }

        public:
        TableBrief(TsharkDB *con) : con{con} {
            check_table();
            TsharkDB::ProtectedDB db = con->get_db();
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
            stat_insert = std::make_unique<SQLite::Statement>(*db, sql);
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
            stat_delete = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE
                (CASE WHEN @frame_protocol IS NOT NULL THEN frame_protocol LIKE @frame_protocol ELSE TRUE END) AND
                (CASE WHEN @src_location IS NOT NULL THEN src_location LIKE @src_location ELSE TRUE END) AND
                (CASE WHEN @dst_location IS NOT NULL THEN dst_location LIKE @dst_location ELSE TRUE END) AND
                (CASE WHEN @src_mac IS NOT NULL THEN src_mac LIKE @src_mac ELSE TRUE END) AND
                (CASE WHEN @dst_mac IS NOT NULL THEN dst_mac LIKE @dst_mac ELSE TRUE END) AND
                (CASE WHEN @src_ip IS NOT NULL THEN src_ip LIKE @src_ip ELSE TRUE END) AND
                (CASE WHEN @dst_ip IS NOT NULL THEN dst_ip LIKE @dst_ip ELSE TRUE END) AND
                (CASE WHEN @src_port IS NOT NULL THEN src_port = @src_port ELSE TRUE END) AND
                (CASE WHEN @dst_port IS NOT NULL THEN dst_port = @dst_port ELSE TRUE END) AND
                (CASE WHEN @cap_len IS NOT NULL THEN cap_len = @cap_len ELSE TRUE END)
                LIMIT @size OFFSET @pos
            )";
            sql = fmt::format(sql, name);
            stat_select = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE idx = @idx
            )";
            sql = fmt::format(sql, name);
            stat_select_one = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT count(*) from {}
            )";
            sql = fmt::format(sql, name);
            stat_size = std::make_unique<SQLite::Statement>(*db, sql);
            size(true);
        }

        uint32_t size(bool update = false) {
            if (!update) return total_count;
            if (!stat_size) return 0;
            TsharkDB::ProtectedDB db = con->get_db();
            stat_size->reset();
            try {
                if (stat_size->executeStep()) {
                    total_count = stat_size->getColumn(0).getUInt();
                    return total_count;
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        int clear() {
            TsharkDB::ProtectedDB db = con->get_db();
            std::string sql = R"(
                DELETE FROM {}
            )";
            sql = fmt::format(sql, name);
            auto ret = exec(sql);
            if (ret) total_count = 0;
            return ret;
        }

        int check_table() {
            TsharkDB::ProtectedDB db = con->get_db();
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
            TsharkDB::ProtectedDB db = con->get_db();
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
                // LOG_F(INFO, "%s", stat_insert->getExpandedSQL().c_str());
                if (stat_insert->exec()) {
                    total_count++;
                    return 1;
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        int delete_one(uint32_t idx) {
            if (!stat_delete) return 0;
            TsharkDB::ProtectedDB db = con->get_db();
            try {
                stat_delete->reset();
                stat_delete->bind(1, idx);
                if (stat_insert->exec()) {
                    total_count--;
                    return 1;
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        std::shared_ptr<Packet> select(uint32_t idx, TableFixed &dbfixed) {
            if (!stat_select_one) return nullptr;
            TsharkDB::ProtectedDB db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            try {
                stat_select_one->reset();
                stat_select_one->bind("@idx", idx);
                if (stat_select_one->executeStep()) {
                    auto ret = compose_packet(*stat_select_one, dbfixed);
                    return ret;
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return nullptr;
        }

        std::vector<std::shared_ptr<Packet>> select(
            uint32_t pos, uint32_t size, TableFixed &dbfixed) {
            std::vector<std::shared_ptr<Packet>> ret;
            if (!stat_select) return ret;
            TsharkDB::ProtectedDB db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            try {
                stat_select->reset();
                stat_select->clearBindings();
                stat_select->bind("@pos", pos);
                stat_select->bind("@size", size);
                while (stat_select->executeStep()) {
                    ret.push_back(compose_packet(*stat_select, dbfixed));
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return ret;
        }

        std::vector<std::shared_ptr<Packet>> select(
            std::unordered_map<std::string, std::string> params,
            TableFixed &dbfixed) {
            std::vector<std::shared_ptr<Packet>> ret;
            if (!stat_select) return ret;
            TsharkDB::ProtectedDB db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            static const std::unordered_set<char const *> NumberParams = {
                "pos", "size", "src_port", "dst_port", "cap_len"};
            std::unordered_map<std::string, std::string> valid_params;
            for (auto &i : params) {
                if (stat_select->getIndex(("@" + i.first).c_str()) &&
                    !i.second.empty()) {
                    if (!NumberParams.count(i.second.c_str())) {
                        i.second = utils_sql_fuzz_escape(i.second);
                        i.second = utils_replace_str_all(i.second, "*", "%");
                    }
                    valid_params.emplace(i.first, i.second);
                }
            }
            try {
                stat_select->reset();
                stat_select->clearBindings();
                stat_select->bind("@pos", 0);
                stat_select->bind("@size", 999999999);
                for (auto &i : valid_params) {
                    std::string param = "@" + i.first;
                    if (NumberParams.count(param.c_str())) {
                        try {
                            stat_select->bind(param,
                                static_cast<uint32_t>(std::stoul(i.second)));
                        }
                        catch (...) {
                        }
                    }
                    else
                        stat_select->bind(param, i.second);
                }
                LOG_F(INFO, "%s", stat_select->getExpandedSQL().c_str());
                while (stat_select->executeStep()) {
                    ret.push_back(compose_packet(*stat_select, dbfixed));
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return ret;
        }
    };

    private:
    std::shared_mutex mt;
    std::unique_ptr<SQLite::Database> db;
    std::unique_ptr<SQLite::Transaction> transaction;

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
    std::unique_ptr<TableFixed> table_fixed;
    std::unique_ptr<TableBrief> table_brief;

    TsharkDB(TsharkDB &&other) {
        this->db = std::move(other.db);
        this->transaction = std::move(other.transaction);
        this->table_fixed = std::move(other.table_fixed);
        this->table_brief = std::move(other.table_brief);
    }

    static std::shared_ptr<TsharkDB> connect(std::string const &path) {
        auto ret = std::make_shared<TsharkDB>(TsharkDB(path));
        if (ret->db) {
            ret->table_fixed = std::make_unique<TableFixed>(ret.get());
            ret->table_brief = std::make_unique<TableBrief>(ret.get());
        }
        return ret;
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

    void recreate() {
        std::unique_lock<std::shared_mutex> lock(mt);
        if (has_transaction()) commit_transaction();
        std::filesystem::path path = db->getFilename();

        table_fixed.reset();
        table_brief.reset();
        db.reset();
        if (std::filesystem::exists(path) &&
            std::filesystem::is_regular_file(path)) {
            std::filesystem::remove(path);
        }
        db = std::make_unique<SQLite::Database>(
            path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
        lock.unlock();
        table_fixed = std::make_unique<TableFixed>(this);
        table_brief = std::make_unique<TableBrief>(this);
    }

    ProtectedDB get_db() {
        return ProtectedDB(this, mt);
    }

    ~TsharkDB() {
        if (has_transaction()) commit_transaction();
    }
};