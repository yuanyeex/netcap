package com.yuanyeex.netcap;

import com.google.common.base.Preconditions;
import com.yuanyeex.netcap.capture.PacketProcessor;
import com.yuanyeex.netcap.capture.PcapHandleCapture;
import com.yuanyeex.netcap.capture.handler.ConsoleLogDnsPacketHandler;
import com.yuanyeex.netcap.capture.handler.DnsPacketHandler;
import com.yuanyeex.netcap.capture.handler.KafkaDnsPacketHandler;
import com.yuanyeex.netcap.config.PropertyKey;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;

import static com.yuanyeex.netcap.config.PropertyKey.KAFKAKey.*;

/**
 * Dns Capture and send to kafka stream bootstrap class.
 */
public class DnsCaptureMain {

    private static final Logger logger = LoggerFactory.getLogger("pcap-main");

    public static void main(String[] args) {
        logger.info("Start!");
        Properties properties = parseArgs(args);
        Preconditions.checkNotNull(properties, "properties cannot be loaded - " + Arrays.toString(args));
        try {
            DnsPacketHandler dnsPacketHandler = getDnsPacketHandler(properties);
            PacketProcessor.startProcessor(dnsPacketHandler);
            PcapHandleCapture.startCapture(properties);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }

    private static DnsPacketHandler getDnsPacketHandler(Properties properties) {

        String enableKafka = properties.getProperty(PropertyKey.KAFKAKey.kafkaEnabled.getKey());
        if (!StringUtils.equals("true", enableKafka)) {
            return ConsoleLogDnsPacketHandler.INSTANCE;
        }

        String topic = properties.getProperty(kafkaTopic.getKey());
        Preconditions.checkArgument(StringUtils.isNotBlank(topic), "kafka topic missing");

        String bootstrapservers = properties.getProperty(kafkaBootstrapServers.getKey());
        Preconditions.checkArgument(StringUtils.isNotBlank(bootstrapservers), "kafka bootstrap servers missing!");

        String acks = properties.getProperty(kafkaAcks.getKey(), kafkaAcks.getDefaultValue());
        String retries = properties.getProperty(kafkaRetries.getKey(), kafkaRetries.getDefaultValue());
        String lingerMs = properties.getProperty(kafkaLingerMs.getKey(), kafkaLingerMs.getDefaultValue());
        String keySerializer = properties.getProperty(kafkaKeySerializer.getKey());
        Preconditions.checkArgument(StringUtils.isNotBlank(keySerializer), "kafka key serializer missing!");
        String valueSerializer = properties.getProperty(kafkaValueSerializer.getKey());
        Preconditions.checkArgument(StringUtils.isNotBlank(valueSerializer), "kafka value serializer missing!");

        Properties kafkaProperties = new Properties();
        kafkaProperties.put("bootstrap.servers", bootstrapservers);
        kafkaProperties.put("acks", acks);
        kafkaProperties.put("retries", Integer.parseInt(retries));
        kafkaProperties.put("linger.ms", Integer.parseInt(lingerMs));
        kafkaProperties.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        kafkaProperties.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");


        Producer<String, String> producer = new KafkaProducer<String, String>(kafkaProperties);

        KafkaDnsPacketHandler kafkaDnsPacketHandler = new KafkaDnsPacketHandler();
        kafkaDnsPacketHandler.setProducer(producer);
        kafkaDnsPacketHandler.setTopic(topic);

        return kafkaDnsPacketHandler;
    }

    private static Properties parseArgs(String[] args) {
        Options dnsCaptureOptions = new Options()
                .addRequiredOption("c", "conf", true, "[required]config file path")
                .addOption("h", "help", false, "show help info");

        DefaultParser defaultParser = new DefaultParser();
        try {
            CommandLine commandLine = defaultParser.parse(dnsCaptureOptions, args);
            if (commandLine.hasOption("h")) {
                printHelp(dnsCaptureOptions);
                exit(0);
            } else {
                String configFileStr = commandLine.getOptionValue("c");
                InputStream configInputStream = validateConfigFile(configFileStr);
                return loadConfiguredProperties(configInputStream);
            }

        }
        catch (MissingOptionException mae) {
            System.err.println("Missing argument: " + mae.getMessage());
            printHelp(dnsCaptureOptions);
            exit(-10);
        }
        catch (Exception e) {
            e.printStackTrace();
            exit(-100);
        }

        return null;
    }

    private static void printHelp(Options options) {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("DnsCaptureMain", options);
    }

    private static void exit(int code) {
        System.exit(code);
    }

    private static InputStream validateConfigFile(String configFile) throws FileNotFoundException {
        InputStream resourceAsStream = DnsCaptureMain.class.getResourceAsStream(configFile);
        if (resourceAsStream != null) {
            return resourceAsStream;
        }
        File file = new File(configFile);
        if (!file.exists()) {
            throw new IllegalArgumentException(String.format("the config file (%s) not exist, full path: %s",
                    configFile, file.getAbsoluteFile()));
        }
        if (!file.isFile()) {
            throw new IllegalArgumentException(String.format("the config path (%s) is not a file",
                    file.getAbsoluteFile()));
        }
        return new FileInputStream(file);
    }

    private static Properties loadConfiguredProperties(InputStream inputStream) throws IOException {
        try (InputStream is = inputStream) {
            Properties properties = new Properties();
            properties.load(is);
            return properties;
        }
    }
}
