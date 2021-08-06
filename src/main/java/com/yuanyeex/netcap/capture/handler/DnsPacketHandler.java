package com.yuanyeex.netcap.capture.handler;

import org.pcap4j.packet.DnsPacket;

public interface DnsPacketHandler {
    void handle(DnsPacket packet);
}
