package com.yuanyeex.netcap.config;

import org.pcap4j.core.PcapNetworkInterface;

public interface PropertyKey {

    default boolean isRequired() {
        return false;
    }

    String getKey();

    String getDefaultValue();

    /**
     * Packet capturing properties
     */
    enum PCAPKey implements PropertyKey {
        /**
         * [Integer] Snapshot length. Integer, should be positive.
         */
        PCAP_SNAPLEN("pcap.snaplen", "65536"),
        /**
         * [Integer] pcap timeout in milliseconds
         */
        PCAP_TIMEOUT_MILLS("pcap.timeout.mills", "10"),
        /**
         * [String] the interface deviceName for capturing. A value
         * {@link PcapNetworkInterface#getName()} returns.
         */
        PCAP_NETWORK_INTERFACE_DEVICE_NAME("pcap.network.interface.device.name", "") {
            @Override
            public boolean isRequired() {
                return true;
            }
        },
        /**
         * [Boolean] is pcap network interface promiscous mode
         */
        PCAP_NETWORK_INTERFACE_PROMISCUOUS_MODE("pcap.network.interface.promiscuous.mode", "true"),
        /**
         * [String] the BPF pattern string.
         */
        PCAP_BPF_PATTERN("pcap.bpf.pattern", ""),
        /**
         * [Boolean] is bpf compile in optimized mode
         */
        PCAP_BPF_COMPILE_OPTIMIZED_MODE("pcap.bpf.compile.optimized.mode", "true");


        private final String key;
        private final String defaultValue;

        PCAPKey(String key, String defaultValue) {
            this.key = key;
            this.defaultValue = defaultValue;
        }

        @Override
        public String getKey() {
            return key;
        }

        @Override
        public String getDefaultValue() {
            return defaultValue;
        }
    }


}
