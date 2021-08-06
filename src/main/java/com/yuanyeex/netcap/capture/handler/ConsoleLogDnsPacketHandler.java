package com.yuanyeex.netcap.capture.handler;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

public class ConsoleLogDnsPacketHandler implements DnsPacketHandler {

    private static final Logger logger = LoggerFactory.getLogger("console-pkg-handler");

    public static final ConsoleLogDnsPacketHandler INSTANCE = new ConsoleLogDnsPacketHandler();

    private ConsoleLogDnsPacketHandler() {}

    @Override
    public void handle(DnsPacket dnsPacket) {
        DnsPacket.DnsHeader header = dnsPacket.getHeader();
        StringBuilder sb = new StringBuilder();
        sb.append("log")
                .append(" with ").append(header.getQdCount());
        List<DnsQuestion> questions = header.getQuestions();
        for (DnsQuestion question : questions) {
            sb.append(" ").append(question.getQName());
        }

        System.out.println(sb.toString());
        if (logger.isInfoEnabled()) {
            String dnsQueried = questions.stream().map(DnsQuestion::getQName).map(DnsDomainName::getName).collect(Collectors.joining(","));
            logger.info("handle packet, cnt={}, qNames: {}",
                    header.getQdCount(), dnsQueried);
        }

    }
}
