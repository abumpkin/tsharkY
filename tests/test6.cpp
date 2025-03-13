#include "database.h"
#include "fmt/format.h"
#include "mutils.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <traffic_statistics.h>
#include <unistream.h>
#include <unordered_map>
#include <utility>

void test() {
    std::filesystem::path path = "dump_data/big.pcap";
    std::cout << "SQlite3 version " << SQLite::VERSION << " ("
              << SQLite::getLibVersion() << ")" << std::endl;
    std::cout << "SQliteC++ version " << SQLITECPP_VERSION << std::endl;
    ////////////////////////////////////////////////////////////////////////////
    // Simple batch queries example :
    try {
        // Open a database file in create/write mode
        SQLite::Database db(
            "test.db3", SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
        std::cout << "SQLite database file '" << db.getFilename().c_str()
                  << "' opened successfully\n";

        // Create a new table with an explicit "id" column aliasing the
        // underlying rowid
        db.exec("DROP TABLE IF EXISTS test");
        db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");

        // first row
        int nb = db.exec("INSERT INTO test VALUES (NULL, \"test\")");
        std::cout << "INSERT INTO test VALUES (NULL, \"test\")\", returned "
                  << nb << std::endl;

        // second row
        nb = db.exec("INSERT INTO test VALUES (NULL, \"second\")");
        std::cout << "INSERT INTO test VALUES (NULL, \"second\")\", returned "
                  << nb << std::endl;

        // update the second row
        nb = db.exec("UPDATE test SET value=\"second-updated\" WHERE id='2'");
        std::cout << "UPDATE test SET value=\"second-updated\" WHERE id='2', "
                     "returned "
                  << nb << std::endl;

        // Check the results : expect two row of result
        SQLite::Statement query(db, "SELECT * FROM test");
        std::cout << "SELECT * FROM test :\n";
        while (query.executeStep()) {
            std::cout << "row (" << query.getColumn(0) << ", \""
                      << query.getColumn(1) << "\")\n";
        }

        db.exec("DROP TABLE test");
    }
    catch (std::exception &e) {
        std::cout << "SQLite exception: " << e.what() << std::endl;
    }
    remove("test.db3");

    std::cout << "everything ok, quitting\n";
}

int main() {
    auto db = TsharkDB::connect("dump_data/temp.db3");
    DBBriefTable t{db};
    DBFixed f{db};
    {
        utils_timer time;
        int c = 4;
        uint32_t ret;
        while (c--) {
            time.beg();
            ret = t.size();
            time.end();
        }
        std::cout << ret << std::endl;
    }
    {
        utils_timer time;
        int c = 4;
        while (c--) {
            time.beg();
            auto data = t.select(0, 1000, f);
            // for (auto &i : data) {
            //     std::cout << i->to_json() << std::endl;
            // }
            time.end();
        }
    }
    {
        utils_timer time;
        int c = 4;
        while (c--) {
            time.beg();
            auto data = t.select(1000000, 1000, f);
            // for (auto &i : data) {
            //     std::cout << i->to_json() << std::endl;
            // }
            time.end();
        }
    }
    return 0;
}