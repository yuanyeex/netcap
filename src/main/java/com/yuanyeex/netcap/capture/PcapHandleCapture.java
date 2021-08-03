package com.yuanyeex.netcap.capture;

import com.yuanyeex.netcap.config.PropertyKey.PCAPKey;
import org.apache.commons.lang3.StringUtils;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Properties;

public class PcapHandleCapture {

    private static final Logger logger = LoggerFactory.getLogger("netcap-pcap");

    public static void startCapture(Properties properties) throws PcapNativeException, NotOpenException {
        PcapHandle pcapHandle = null;
        try {
            pcapHandle = buildPcapHandle(properties);
            pcapHandle.loop(-1, new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    try {
                        PacketProcessor.submitPacket(packet);
                    } catch (InterruptedException e) {
                        logger.error("PacketProcessor is interrupted!");
                    }

                }
            });
        } catch (InterruptedException e) {
            logger.error("PcapCapture is interrupted!");
        } finally {
            if (pcapHandle != null) {
                pcapHandle.close();
            }
        }

    }

    private static PcapHandle buildPcapHandle(Properties properties) throws PcapNativeException, NotOpenException {
        String deviceName = getString(properties, PCAPKey.PCAP_NETWORK_INTERFACE_DEVICE_NAME);

        Integer snapLen = getInteger(properties, PCAPKey.PCAP_SNAPLEN);
        Objects.requireNonNull(snapLen, String.format("timeoutMills[%s] is not correctly set", PCAPKey.PCAP_TIMEOUT_MILLS.getKey()));

        Integer timeoutMills = getInteger(properties, PCAPKey.PCAP_TIMEOUT_MILLS);
        Objects.requireNonNull(timeoutMills, String.format("timeoutMills[%s] is not correctly set", PCAPKey.PCAP_TIMEOUT_MILLS.getKey()));

        Boolean promiscuousModeVal = getBoolean(properties, PCAPKey.PCAP_NETWORK_INTERFACE_PROMISCUOUS_MODE);
        PcapNetworkInterface.PromiscuousMode promiscuousMode = promiscuousModeVal
                ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;

        String bpfPattern = getString(properties, PCAPKey.PCAP_BPF_PATTERN);
        Boolean bpfOptimizedMode = getBoolean(properties, PCAPKey.PCAP_BPF_COMPILE_OPTIMIZED_MODE);
        BpfProgram.BpfCompileMode compileMode = bpfOptimizedMode
                ? BpfProgram.BpfCompileMode.OPTIMIZE
                : BpfProgram.BpfCompileMode.NONOPTIMIZE;

        PcapNetworkInterface pcapNetworkInterface = getPcapNetworkInterface(deviceName);

        if (pcapNetworkInterface == null) {
            throw new IllegalArgumentException("NetworkInterface with name [" + deviceName + "]" + " does not exist!");
        }

        PcapHandle pcapHandle = pcapNetworkInterface.openLive(snapLen, promiscuousMode, timeoutMills);

        pcapHandle.setFilter(bpfPattern, compileMode);

        return pcapHandle;
    }


    private static PcapNetworkInterface getPcapNetworkInterface(String deviceName) throws PcapNativeException {
        if (StringUtils.isBlank(deviceName)) {
            throw new IllegalArgumentException(String.format("deviceName/%s is required", PCAPKey.PCAP_NETWORK_INTERFACE_DEVICE_NAME.getKey()));
        }

        return Pcaps.getDevByName(deviceName);
    }

    private static String getString(Properties properties, PCAPKey pcapKey) {
        String value = properties.getProperty(pcapKey.getKey());
        if (value == null) {
            if (pcapKey.isRequired()) {
                throw new IllegalArgumentException("property: " + pcapKey.getKey() + " is required!");
            }
            value = pcapKey.getDefaultValue();
        }
        return value;
    }

    private static Integer getInteger(Properties properties, PCAPKey pcapKey) {
        String value = getString(properties, pcapKey);
        if (StringUtils.isBlank(value)) {
            return null;
        }
        return Integer.parseInt(value);
    }

    private static Boolean getBoolean(Properties properties, PCAPKey pcapKey) {
        String value = getString(properties, pcapKey);
        return Boolean.valueOf(value);
    }
}
