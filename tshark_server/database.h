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
#include "mutils.h"
#include "tshark_info.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fmt/core.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct TableField {
    const int bind_index;
    const char *field_name;
    const char *field_def;
    TableField(int bind_index, const char *field_name, const char *field_def)
        : bind_index(bind_index), field_name(field_name),
          field_def(field_def) {};
    explicit operator int() const {
        return bind_index;
    }
    operator const char *() const {
        return field_name;
    }
    bool operator==(TableField const &t) const {
        return bind_index == t.bind_index;
    }
    std::string def() const {
        return std::string(field_name) + " " + field_def;
    }
};

template <typename T>
struct TableFieldDefBase {
    constexpr int size() const {
        return sizeof(T) / sizeof(TableField);
    }

    std::vector<std::string> field_def_list() const {
        std::vector<std::string> ret;
        const T *pthis = static_cast<const T *>(this);
        const TableField *p = reinterpret_cast<const TableField *>(pthis);
        for (int i = 0; i < size(); i++) {
            ret.push_back(p->def());
            p++;
        }
        return ret;
    }
};

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

    struct TableBase {
        TsharkDB *con;
        const char *name;
        const char *get_table_name() const {
            return name;
        }
        TableBase(TsharkDB *con, const char *name) : con(con), name(name) {};
        TableBase(TableBase &) = delete;
        TableBase(TableBase &&) = delete;
        TableBase &operator=(TableBase &) = delete;
        TableBase &operator=(TableBase &&) = delete;

        protected:
        virtual int exec(std::string const &sql) {
            auto db = con->get_db();
            try {
                return db->exec(sql);
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return 0;
        }

        virtual int clear() {
            auto db = con->get_db();
            std::string sql = R"(
                DELETE FROM {}
            )";
            sql = fmt::format(sql, name);
            auto ret = exec(sql);
            return ret;
        }
    };

    struct FixedDataTable : TableBase {
        private:
        std::shared_ptr<std::vector<char>> fixed;
        std::string format;
        std::unique_ptr<SQLite::Statement> stat_insert;
        std::unique_ptr<SQLite::Statement> stat_delete;
        std::unique_ptr<SQLite::Statement> stat_select;

        public:
        FixedDataTable(TsharkDB *con) : TableBase(con, "fixed_data") {
            check_table();
            auto db = con->get_db();
            std::string sql = R"(
                INSERT OR REPLACE INTO {} VALUES (
                    @format,
                    @data
                )
            )";
            sql = fmt::format(sql, name);
            stat_insert = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT data, format FROM {} LIMIT 1
            )";
            sql = fmt::format(sql, name);
            stat_select = std::make_unique<SQLite::Statement>(*db, sql);
        }

        int check_table() {
            auto db = con->get_db();
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
            auto db = con->get_db();
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
            auto db = con->get_db();
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

    struct PacketTable : TableBase {
        private:
        struct TableFieldDef : TableFieldDefBase<TableFieldDef> {
            const TableField idx = //
                {1, "idx", "INTEGER PRIMARY KEY ON CONFLICT REPLACE"};
            const TableField frame_timestamp = //
                {2, "frame_timestamp", "NUMERIC DEFAULT 0"};
            const TableField frame_protocol = //
                {3, "frame_protocol", "TEXT"};
            const TableField frame_info = //
                {4, "frame_info", "TEXT"};
            const TableField src_location = //
                {5, "src_location", "TEXT"};
            const TableField dst_location = //
                {6, "dst_location", "TEXT"};
            const TableField src_mac = //
                {7, "src_mac", "TEXT"};
            const TableField dst_mac = //
                {8, "dst_mac", "TEXT"};
            const TableField src_ip = //
                {9, "src_ip", "TEXT"};
            const TableField dst_ip = //
                {10, "dst_ip", "TEXT"};
            const TableField src_port = //
                {11, "src_port", "INTEGER"};
            const TableField dst_port = //
                {12, "dst_port", "INTEGER"};
            const TableField cap_off = //
                {13, "cap_off", "INTEGER"};
            const TableField cap_len = //
                {14, "cap_len", "INTEGER"};
            const TableField data = //
                {15, "data", "BLOB"};
            const TableField session_id = //
                {16, "session_id",
                    "INTEGER REFERENCES packet_table(idx) ON DELETE CASCADE ON "
                    "UPDATE CASCADE"};
        } Fields;
        std::unique_ptr<SQLite::Statement> stat_insert;
        std::unique_ptr<SQLite::Statement> stat_delete;
        std::unique_ptr<SQLite::Statement> stat_select_one;
        std::unique_ptr<SQLite::Statement> stat_select;
        std::unique_ptr<SQLite::Statement> stat_rselect_one;
        std::unique_ptr<SQLite::Statement> stat_size;
        uint32_t total_count;

        inline std::shared_ptr<Packet> compose_packet(
            SQLite::Statement &stat, FixedDataTable &dbfixed) {
            std::shared_ptr<Packet> p = std::make_shared<Packet>();
            p->idx = stat.getColumn(Fields.idx).getUInt();
            p->frame_timestamp =
                stat.getColumn(Fields.frame_timestamp).getString();
            p->frame_protocol =
                stat.getColumn(Fields.frame_protocol).getString();
            p->frame_info = stat.getColumn(Fields.frame_info).getString();
            p->src_location = stat.getColumn(Fields.src_location).getString();
            p->dst_location = stat.getColumn(Fields.dst_location).getString();
            p->src_mac = stat.getColumn(Fields.src_mac).getString();
            p->dst_mac = stat.getColumn(Fields.dst_mac).getString();
            p->src_ip = stat.getColumn(Fields.src_ip).getString();
            p->dst_ip = stat.getColumn(Fields.dst_ip).getString();
            p->src_port = stat.getColumn(Fields.src_port).getUInt();
            p->dst_port = stat.getColumn(Fields.dst_port).getUInt();
            p->cap_off = stat.getColumn(Fields.cap_off).getUInt();
            p->cap_len = stat.getColumn(Fields.cap_len).getUInt();
            p->sess_idx = stat.getColumn(Fields.session_id).getUInt();
            auto data_col = stat.getColumn(Fields.data);
            p->data = std::make_unique<std::vector<char>>(
                static_cast<const char *>(data_col.getBlob()),
                static_cast<const char *>(data_col.getBlob()) +
                    data_col.getBytes());
            p->fixed = dbfixed.get_data();
            return p;
        }

        public:
        PacketTable(TsharkDB *con) : TableBase(con, "packet_table") {
            check_table();
            auto db = con->get_db();
            std::string sql = R"(
            INSERT OR REPLACE INTO {} VALUES (
                :{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{}
            )
            )";
            sql = fmt::format(sql, name,     //
                (int)Fields.idx,             //
                (int)Fields.frame_timestamp, //
                (int)Fields.frame_protocol,  //
                (int)Fields.frame_info,      //
                (int)Fields.src_location,    //
                (int)Fields.dst_location,    //
                (int)Fields.src_mac,         //
                (int)Fields.dst_mac,         //
                (int)Fields.src_ip,          //
                (int)Fields.dst_ip,          //
                (int)Fields.src_port,        //
                (int)Fields.dst_port,        //
                (int)Fields.cap_off,         //
                (int)Fields.cap_len,         //
                (int)Fields.data,            //
                (int)Fields.session_id       //
            );
            // LOG_F(INFO, "%s", sql.c_str());
            stat_insert = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                DELETE FROM {} WHERE idx = :{}
            )";
            sql = fmt::format(sql, name, (int)Fields.idx);
            stat_delete = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} = @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} = @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} = @{} ELSE TRUE END)
                LIMIT @size OFFSET @pos
            )";
            sql = fmt::format(sql, name,             //
                (const char *)Fields.frame_protocol, //
                (const char *)Fields.frame_protocol, //
                (const char *)Fields.frame_protocol, //
                (const char *)Fields.src_location,   //
                (const char *)Fields.src_location,   //
                (const char *)Fields.src_location,   //
                (const char *)Fields.dst_location,   //
                (const char *)Fields.dst_location,   //
                (const char *)Fields.dst_location,   //
                (const char *)Fields.src_mac,        //
                (const char *)Fields.src_mac,        //
                (const char *)Fields.src_mac,        //
                (const char *)Fields.dst_mac,        //
                (const char *)Fields.dst_mac,        //
                (const char *)Fields.dst_mac,        //
                (const char *)Fields.src_ip,         //
                (const char *)Fields.src_ip,         //
                (const char *)Fields.src_ip,         //
                (const char *)Fields.dst_ip,         //
                (const char *)Fields.dst_ip,         //
                (const char *)Fields.dst_ip,         //
                (const char *)Fields.src_port,       //
                (const char *)Fields.src_port,       //
                (const char *)Fields.src_port,       //
                (const char *)Fields.dst_port,       //
                (const char *)Fields.dst_port,       //
                (const char *)Fields.dst_port,       //
                (const char *)Fields.session_id,     //
                (const char *)Fields.session_id,     //
                (const char *)Fields.session_id      //
            );
            stat_select = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE idx < :{} ORDER BY {} DESC LIMIT 1
            )";
            sql = fmt::format(
                sql, name, (int)Fields.idx, (const char *)Fields.idx);
            stat_rselect_one = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE idx = :{}
            )";
            sql = fmt::format(sql, name, (int)Fields.idx);
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
            auto db = con->get_db();
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

        int clear() override {
            int ret = TableBase::clear();
            if (ret) total_count = 0;
            return ret;
        }

        int check_table() {
            auto db = con->get_db();
            std::string sql = R"(
                CREATE TABLE IF NOT EXISTS {} (
                    {}
                ) WITHOUT ROWID
            )";
            sql = fmt::format(
                sql, name, utils_join_str(Fields.field_def_list(), ",\n"));
            // LOG_F(INFO, "%s", sql.c_str());
            return exec(sql);
        }

        int insert(std::shared_ptr<Packet> p) {
            if (!stat_insert) return 0;
            auto db = con->get_db();
            try {
                stat_insert->reset();
                stat_insert->bind((int)Fields.idx, p->idx);
                stat_insert->bind(
                    (int)Fields.frame_timestamp, p->frame_timestamp);
                stat_insert->bind(
                    (int)Fields.frame_protocol, p->frame_protocol);
                stat_insert->bind((int)Fields.frame_info, p->frame_info);
                stat_insert->bind((int)Fields.src_location, p->src_location);
                stat_insert->bind((int)Fields.dst_location, p->dst_location);
                stat_insert->bind((int)Fields.src_mac, p->src_mac);
                stat_insert->bind((int)Fields.dst_mac, p->dst_mac);
                stat_insert->bind((int)Fields.src_ip, p->src_ip);
                stat_insert->bind((int)Fields.dst_ip, p->dst_ip);
                stat_insert->bind((int)Fields.src_port, p->src_port);
                stat_insert->bind((int)Fields.dst_port, p->dst_port);
                stat_insert->bind((int)Fields.cap_off, p->cap_off);
                stat_insert->bind((int)Fields.cap_len, p->cap_len);
                stat_insert->bind((int)Fields.session_id, p->sess_idx);
                stat_insert->bind((int)Fields.data);
                if (p->data)
                    stat_insert->bindNoCopy(
                        (int)Fields.data, p->data->data(), p->data->size());
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
            auto db = con->get_db();
            try {
                stat_delete->reset();
                stat_delete->bind((int)Fields.idx, idx);
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

        std::shared_ptr<Packet> previous(
            uint32_t idx, FixedDataTable &dbfixed) {
            if (!stat_rselect_one) return nullptr;
            auto db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            try {
                stat_rselect_one->reset();
                stat_rselect_one->bind((int)Fields.idx, idx);
                if (stat_rselect_one->executeStep()) {
                    auto ret = compose_packet(*stat_rselect_one, dbfixed);
                    return ret;
                }
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
            return nullptr;
        }

        std::shared_ptr<Packet> select(uint32_t idx, FixedDataTable &dbfixed) {
            if (!stat_select_one) return nullptr;
            auto db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            try {
                stat_select_one->reset();
                stat_select_one->bind((int)Fields.idx, idx);
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
            uint32_t pos, uint32_t size, FixedDataTable &dbfixed) {
            std::vector<std::shared_ptr<Packet>> ret;
            if (!stat_select) return ret;
            auto db = con->get_db();
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
            FixedDataTable &dbfixed) {
            std::vector<std::shared_ptr<Packet>> ret;
            if (!stat_select) return ret;
            auto db = con->get_db();
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

    struct SessionTable : TableBase {
        private:
        struct TableFieldDef : TableFieldDefBase<TableFieldDef> {
            const TableField session_id = //
                {1, "session_id", "INTEGER PRIMARY KEY ON CONFLICT REPLACE"};
            const TableField start_time = //
                {2, "start_time", "NUMERIC DEFAULT 0"};
            const TableField end_time = //
                {3, "end_time", "NUMERIC DEFAULT 0"};
            const TableField ip1 = //
                {4, "ip1", "TEXT"};
            const TableField ip2 = //
                {5, "ip2", "TEXT"};
            const TableField ip1_location = //
                {6, "ip1_location", "TEXT"};
            const TableField ip2_location = //
                {7, "ip2_location", "TEXT"};
            const TableField ip1_port = //
                {8, "ip1_port", "INTEGER"};
            const TableField ip2_port = //
                {9, "ip2_port", "INTEGER"};
            const TableField trans_proto = //
                {10, "trans_proto", "TEXT"};
            const TableField app_proto = //
                {11, "app_proto", "TEXT"};
            const TableField ip1_send_packets = //
                {12, "ip1_send_packets", "INTEGER"};
            const TableField ip2_send_packets = //
                {13, "ip2_send_packets", "INTEGER"};
            const TableField ip1_send_bytes = //
                {14, "ip1_send_bytes", "INTEGER"};
            const TableField ip2_send_bytes = //
                {15, "ip2_send_bytes", "INTEGER"};
            const TableField pacet_count = //
                {16, "packet_count", "INTEGER"};
            const TableField total_bytes = //
                {17, "total_bytes", "INTEGER"};
        } Fields;
        std::unique_ptr<SQLite::Statement> stat_insert;
        std::unique_ptr<SQLite::Statement> stat_delete;
        std::unique_ptr<SQLite::Statement> stat_select_one;
        std::unique_ptr<SQLite::Statement> stat_select;
        std::unique_ptr<SQLite::Statement> stat_size;
        uint32_t total_count;

        inline std::shared_ptr<Session> compose_packet(
            SQLite::Statement &stat) {
            std::shared_ptr<Session> p = Session::create();
            p->session_id = stat.getColumn(Fields.session_id).getUInt();
            p->start_time = stat.getColumn(Fields.start_time).getDouble();
            p->end_time = stat.getColumn(Fields.end_time).getDouble();
            p->ip1 = stat.getColumn(Fields.ip1).getString();
            p->ip2 = stat.getColumn(Fields.ip2).getString();
            p->ip1_location = stat.getColumn(Fields.ip1_location).getString();
            p->ip2_location = stat.getColumn(Fields.ip2_location).getString();
            p->ip1_port = stat.getColumn(Fields.ip1_port).getUInt();
            p->ip2_port = stat.getColumn(Fields.ip2_port).getUInt();
            p->trans_proto = Packet::get_ip_proto_code(
                stat.getColumn(Fields.trans_proto).getString().c_str());
            p->app_proto = stat.getColumn(Fields.app_proto).getString();
            p->ip1_send_packets =
                stat.getColumn(Fields.ip1_send_packets).getUInt();
            p->ip2_send_packets =
                stat.getColumn(Fields.ip2_send_packets).getUInt();
            p->ip1_send_bytes = stat.getColumn(Fields.ip1_send_bytes).getUInt();
            p->ip2_send_bytes = stat.getColumn(Fields.ip2_send_bytes).getUInt();
            p->packet_count = stat.getColumn(Fields.pacet_count).getUInt();
            p->total_bytes = stat.getColumn(Fields.total_bytes).getUInt();
            return p;
        }

        public:
        SessionTable(TsharkDB *con) : TableBase(con, "session_table") {
            check_table();
            auto db = con->get_db();
            std::string sql = R"(
            INSERT OR REPLACE INTO {} VALUES (
                :{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{},:{}
            )
            )";
            sql = fmt::format(sql, name,      //
                (int)Fields.session_id,       //
                (int)Fields.start_time,       //
                (int)Fields.end_time,         //
                (int)Fields.ip1,              //
                (int)Fields.ip2,              //
                (int)Fields.ip1_location,     //
                (int)Fields.ip2_location,     //
                (int)Fields.ip1_port,         //
                (int)Fields.ip2_port,         //
                (int)Fields.trans_proto,      //
                (int)Fields.app_proto,        //
                (int)Fields.ip1_send_packets, //
                (int)Fields.ip2_send_packets, //
                (int)Fields.ip1_send_bytes,   //
                (int)Fields.ip2_send_bytes,   //
                (int)Fields.pacet_count,      //
                (int)Fields.total_bytes       //
            );
            stat_insert = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                DELETE FROM {} WHERE session_id = :{}
            )";
            sql = fmt::format(sql, name, (int)Fields.session_id);
            stat_delete = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END) AND
                (CASE WHEN @{} IS NOT NULL THEN {} LIKE @{} ELSE TRUE END)
                LIMIT @size OFFSET @pos
            )";
            sql = fmt::format(sql, name,           //
                (const char *)Fields.ip1,          //
                (const char *)Fields.ip1,          //
                (const char *)Fields.ip1,          //
                (const char *)Fields.ip2,          //
                (const char *)Fields.ip2,          //
                (const char *)Fields.ip2,          //
                (const char *)Fields.ip1_location, //
                (const char *)Fields.ip1_location, //
                (const char *)Fields.ip1_location, //
                (const char *)Fields.ip2_location, //
                (const char *)Fields.ip2_location, //
                (const char *)Fields.ip2_location, //
                (const char *)Fields.ip1_port,     //
                (const char *)Fields.ip1_port,     //
                (const char *)Fields.ip1_port,     //
                (const char *)Fields.ip2_port,     //
                (const char *)Fields.ip2_port,     //
                (const char *)Fields.ip2_port,     //
                (const char *)Fields.trans_proto,  //
                (const char *)Fields.trans_proto,  //
                (const char *)Fields.trans_proto,  //
                (const char *)Fields.app_proto,    //
                (const char *)Fields.app_proto,    //
                (const char *)Fields.app_proto,    //
                (const char *)Fields.start_time,   //
                (const char *)Fields.start_time,   //
                (const char *)Fields.start_time,   //
                (const char *)Fields.end_time,     //
                (const char *)Fields.end_time,     //
                (const char *)Fields.end_time      //
            );
            stat_select = std::make_unique<SQLite::Statement>(*db, sql);
            sql = R"(
                SELECT * FROM {} WHERE {} = :{}
            )";
            sql = fmt::format(sql, name, (const char *)Fields.session_id,
                (int)Fields.session_id);
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
            auto db = con->get_db();
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

        int check_table() {
            auto db = con->get_db();
            std::string sql = R"(
                CREATE TABLE IF NOT EXISTS {} (
                    {}
                ) WITHOUT ROWID
            )";
            sql = fmt::format(
                sql, name, utils_join_str(Fields.field_def_list(), ",\n"));
            // LOG_F(INFO, "%s", sql.c_str());
            return exec(sql);
        }

        int insert(std::shared_ptr<Session> p) {
            if (!stat_insert) return 0;
            auto db = con->get_db();
            try {
                stat_insert->reset();
                stat_insert->bind((int)Fields.session_id, p->session_id);
                stat_insert->bind((int)Fields.ip1, p->ip1);
                stat_insert->bind((int)Fields.ip2, p->ip2);
                stat_insert->bind((int)Fields.ip1_location, p->ip1_location);
                stat_insert->bind((int)Fields.ip2_location, p->ip2_location);
                stat_insert->bind((int)Fields.ip1_port, p->ip1_port);
                stat_insert->bind((int)Fields.ip2_port, p->ip2_port);
                stat_insert->bind((int)Fields.trans_proto,
                    Packet::get_ip_proto_str(p->trans_proto));
                stat_insert->bind((int)Fields.app_proto, p->app_proto);
                stat_insert->bind((int)Fields.start_time, p->start_time);
                stat_insert->bind((int)Fields.end_time, p->end_time);
                stat_insert->bind(
                    (int)Fields.ip1_send_packets, p->ip1_send_packets);
                stat_insert->bind(
                    (int)Fields.ip2_send_packets, p->ip2_send_packets);
                stat_insert->bind(
                    (int)Fields.ip1_send_bytes, p->ip1_send_bytes);
                stat_insert->bind(
                    (int)Fields.ip2_send_bytes, p->ip2_send_bytes);
                stat_insert->bind((int)Fields.pacet_count, p->packet_count);
                stat_insert->bind((int)Fields.total_bytes, p->total_bytes);
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
            auto db = con->get_db();
            try {
                stat_delete->reset();
                stat_delete->bind((int)Fields.session_id, idx);
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

        std::vector<std::shared_ptr<Session>> select(
            std::unordered_map<std::string, std::string> params) {
            std::vector<std::shared_ptr<Session>> ret;
            if (!stat_select) return ret;
            auto db = con->get_db();
            if (con->has_transaction()) con->commit_transaction();
            static const std::unordered_set<char const *> NumberParams = {
                "pos", "size"};
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
                    ret.push_back(compose_packet(*stat_select));
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
    std::shared_ptr<SQLite::Database> db;
    std::unique_ptr<SQLite::Transaction> transaction;

    TsharkDB(std::string const &path) {
        utils_path_parent_mkdirs(path);
        if (!utils_test_valid_filename(path).empty()) {
            try {
                db = std::make_shared<SQLite::Database>(
                    path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
                db->exec("PRAGMA synchronous = OFF;");
                db->exec("PRAGMA journal_mode = MEMORY;");
                db->exec("PRAGMA cache_size = -10000;");
            }
            catch (std::exception &e) {
                LOG_F(ERROR, "ERROR: %s", e.what());
            }
        }
        if (db) {
            table_fixed = std::make_unique<FixedDataTable>(this);
            table_brief = std::make_unique<PacketTable>(this);
            table_session = std::make_unique<SessionTable>(this);
        }
    }

    TsharkDB() = default;

    public:
    std::unique_ptr<FixedDataTable> table_fixed;
    std::unique_ptr<PacketTable> table_brief;
    std::unique_ptr<SessionTable> table_session;

    TsharkDB &operator=(TsharkDB &&) = delete;
    TsharkDB(TsharkDB &&other) {
        this->db = std::move(other.db);
        this->transaction = std::move(other.transaction);
    }

    static std::shared_ptr<TsharkDB> connect(std::string const &path) {
        auto ret = std::make_shared<TsharkDB>(TsharkDB());
        new (ret.get()) TsharkDB(path);
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

    void close() {
        std::unique_lock<std::shared_mutex> lock(mt);
        if (has_transaction()) commit_transaction();
        table_fixed.reset();
        table_brief.reset();
        table_session.reset();
        db.reset();
    }

    void recreate() {
        if (!db) return;
        std::filesystem::path path = db->getFilename();
        close();
        if (std::filesystem::exists(path) &&
            std::filesystem::is_regular_file(path)) {
            std::filesystem::remove(path);
        }
        new (this) TsharkDB(path.generic_string());
    }

    ProtectedObj<SQLite::Database> get_db() {
        return ProtectedObj(db, mt);
    }

    ~TsharkDB() {
        std::unique_lock<std::shared_mutex> lock(mt);
        if (has_transaction()) commit_transaction();
    }
};