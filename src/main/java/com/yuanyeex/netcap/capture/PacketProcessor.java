package com.yuanyeex.netcap.capture;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

public class PacketProcessor {

    private static final Logger logger = LoggerFactory.getLogger("packet-process");

    private static final PacketProcessor INSTANCE =
            new PacketProcessor(1024, true);

    private final LinkedBlockingQueue<Packet> packetsQueue;
    private final boolean dropWhenQueueFull;

    private final AtomicLong droppedCount = new AtomicLong(0);

    private final int processorCount;
    private final  ExecutorService executorService;

    private PacketProcessor(int queueLength, boolean dropWhenQueueFull) {
        this.packetsQueue = new LinkedBlockingQueue<>(queueLength);
        this.dropWhenQueueFull = dropWhenQueueFull;
        processorCount = getProcessThreads();
        executorService = Executors.newFixedThreadPool(processorCount,
                new ThreadFactoryBuilder().setDaemon(true).setNameFormat("pkt-proc-%d").build());
    }

    private int getProcessThreads() {
        return Math.min(8, Runtime.getRuntime().availableProcessors());
    }

    private void start() {
        System.out.println("start " + processorCount + " process tasks");
        logger.info("start with {} processor tasks", processorCount);
        for (int i = 0; i < processorCount; i++) {
            executorService.submit(new PacketConsumer(packetsQueue, i));
        }
    }

    private void submit(Packet packet) throws InterruptedException {
        if (packet == null) {
            return;
        }

        boolean offer = this.packetsQueue.offer(packet);
        if (!offer) {
            if (dropWhenQueueFull) {
                droppedCount.incrementAndGet();
                return;
            }

            this.packetsQueue.put(packet);
        }
    }

    private static class PacketConsumer implements Runnable {
        private static final AtomicLong procIdx = new AtomicLong(0);
        private final LinkedBlockingQueue<Packet> consumingQueue;
        private final int consumerId;

        private static long getProcIdx() {
            return procIdx.getAndIncrement();
        }

        private PacketConsumer(LinkedBlockingQueue<Packet> consumingQueue, int consumerId) {
            this.consumingQueue = consumingQueue;
            this.consumerId = consumerId;
        }

        @Override
        public void run() {
            while (true) {
                try {
                    doConsume();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    logger.error("consumer {} is interrupted!", consumerId, e);
//                    return;
                }
            }
        }

        private void doConsume() throws InterruptedException {
            Packet take = consumingQueue.take();
            DnsPacket dnsPacket = getDnsPacket(take, new AtomicLong(0));
            if (dnsPacket != null) {
                long procIdx = getProcIdx();
                DnsPacket.DnsHeader header = dnsPacket.getHeader();
                if (!header.isResponse()) {
                    // 只统计请求
                    StringBuilder sb = new StringBuilder();
                    sb.append("Consumer ").append(consumerId).append(" consumes ").append(procIdx)
                            .append(" with ").append(header.getQdCount());
                    List<DnsQuestion> questions = header.getQuestions();
                    for (DnsQuestion question : questions) {
                        sb.append(" ").append(question.getQName());
                    }

                    System.out.println(sb.toString());
                }
            }
        }


        private DnsPacket getDnsPacket(Packet packet, AtomicLong searchDepth) {
            if (packet == null) {
                return null;
            }
            long l = searchDepth.incrementAndGet();
            Packet payload = packet.getPayload();
            if (payload == null) {
                return null;
            }

            if (payload instanceof DnsPacket) {
                return (DnsPacket) payload;
            }

            if (l > 10) {
                return null;
            }

            return getDnsPacket(payload, searchDepth);
        }
    }


    // init and start
    public static void startProcessor() {
        logger.info("Start processor!");
        PacketProcessor.INSTANCE.start();
    }

    public static void submitPacket(Packet packet) throws InterruptedException {
        PacketProcessor.INSTANCE.submit(packet);
    }

}
