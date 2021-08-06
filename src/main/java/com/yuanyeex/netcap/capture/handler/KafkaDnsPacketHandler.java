package com.yuanyeex.netcap.capture.handler;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;

import java.util.List;

@Setter
@Getter
@Accessors(chain = true)
public class KafkaDnsPacketHandler implements DnsPacketHandler {
    @NonNull
    private String topic;
    private Producer<String, String> producer;

    public KafkaDnsPacketHandler() {
    }

    @Override
    public void handle(DnsPacket packet) {
        if (packet != null && packet.getHeader() != null) {
            DnsPacket.DnsHeader header = packet.getHeader();
            // handle query only
            if (!header.isResponse()) {
                List<DnsQuestion> questions = header.getQuestions();
                for (DnsQuestion question : questions) {
                    DnsDomainName qName = question.getQName();
                    String name = qName.getName();
                    ProducerRecord<String, String> record =
                            new ProducerRecord<>(topic, name, name);
                    producer.send(record);
                }
            }
        }
    }

}
