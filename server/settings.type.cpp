#include <iodata-qt5/validator>
#include "settings.type.h"
iodata::validator * settings_data_validator(){
static bool init_done = false;
static iodata::validator A;
static iodata::/*validator::*/record_type record_type1 = { "empty_t", vector<iodata::/*validator::*/node*>(0) };
static iodata::/*validator::*/record_type record_type2 = { "generic_zone_t", vector<iodata::/*validator::*/node*>(1) };
static iodata::/*validator::*/record_type record_type3 = { "key_int_t", vector<iodata::/*validator::*/node*>(2) };
static iodata::/*validator::*/record_type record_type4 = { "manual_offset_t", vector<iodata::/*validator::*/node*>(1) };
static iodata::/*validator::*/record_type record_type5 = { "settings_t", vector<iodata::/*validator::*/node*>(15) };
static iodata::/*validator::*/node_bytes node1("value", 0, 0, "[unknown]");
static iodata::/*validator::*/node_bytes node2("key", 0, 1, "");
static iodata::/*validator::*/node_integer node3("value", 0, 0, 0);
static iodata::/*validator::*/node_integer node4("value", 0, 0, -1);
static iodata::/*validator::*/node_integer node5("time_nitz", 0, 0, -1);
static iodata::/*validator::*/node_integer node6("local_cellular", 0, 0, -1);
static iodata::/*validator::*/node_integer node7("format_24", 0, 0, -1);
static iodata::/*validator::*/node_integer node8("auto_dst", 0, 0, 1);
static iodata::/*validator::*/node_record node9("manual_utc", 0, 0, "empty_t", &record_type1);
static iodata::/*validator::*/node_record node10("nitz_utc", 0, 0, "empty_t", &record_type1);
static iodata::/*validator::*/node_record node11("gps_utc", 0, 0, "empty_t", &record_type1);
static iodata::/*validator::*/node_record node12("ntp_utc", 0, 0, "empty_t", &record_type1);
static iodata::/*validator::*/node_record node13("manual_offset", 0, 0, "manual_offset_t", &record_type4);
static iodata::/*validator::*/node_record node14("nitz_offset", 0, 0, "empty_t", &record_type1);
static iodata::/*validator::*/node_record node15("manual_zone", 0, 0, "generic_zone_t", &record_type2);
static iodata::/*validator::*/node_record node16("cellular_zone", 0, 0, "generic_zone_t", &record_type2);
static iodata::/*validator::*/node_integer node17("default_snooze", 0, 0, 300);
static iodata::/*validator::*/node_record node18("app_snooze", 1, 0, "key_int_t", &record_type3);
static iodata::/*validator::*/node_integer node19("alarms", 0, 0, 1);
if (not init_done) { init_done = true;
A.set_static();
A.types["empty_t"] = &record_type1;
record_type2.nodes[0] = &node1;
A.types["generic_zone_t"] = &record_type2;
record_type3.nodes[0] = &node2;
record_type3.nodes[1] = &node3;
A.types["key_int_t"] = &record_type3;
record_type4.nodes[0] = &node4;
A.types["manual_offset_t"] = &record_type4;
record_type5.nodes[0] = &node5;
record_type5.nodes[1] = &node6;
record_type5.nodes[2] = &node7;
record_type5.nodes[3] = &node8;
record_type5.nodes[4] = &node9;
record_type5.nodes[5] = &node10;
record_type5.nodes[6] = &node11;
record_type5.nodes[7] = &node12;
record_type5.nodes[8] = &node13;
record_type5.nodes[9] = &node14;
record_type5.nodes[10] = &node15;
record_type5.nodes[11] = &node16;
record_type5.nodes[12] = &node17;
record_type5.nodes[13] = &node18;
record_type5.nodes[14] = &node19;
A.types["settings_t"] = &record_type5;
}
return &A;
}

