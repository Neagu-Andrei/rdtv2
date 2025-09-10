FROM docker.elastic.co/logstash/logstash:8.14.3

# Install RELP input plugin
RUN logstash-plugin install logstash-input-relp

# (optional) verify at build time
RUN logstash-plugin list --installed | grep -i relp