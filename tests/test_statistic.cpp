#include "database.h"
#include "analysis.h"


int main() {
    auto db = TsharkDB::connect("dump_data/temp.db3");
    auto sess = db->table_session->select({});
    Analyzer::IpStatistic ip_statistic(sess);
    Analyzer::ProtoStatistic proto_statistic(sess);
    Analyzer::CountryStatistic country_statistic(sess);
    std::cout << ip_statistic.to_json(true) << std::endl;
    std::cout << proto_statistic.to_json(true) << std::endl;
    std::cout << country_statistic.to_json(true) << std::endl;
    return 0;
}