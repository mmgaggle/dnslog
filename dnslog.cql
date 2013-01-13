create keyspace dns_query_count;
create column family counters with default_validation_class=CounterColumnType and key_validation_class=UTF8Type and comparator=UTF8Type;
