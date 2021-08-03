package com.yuanyeex.netcap;

import com.yuanyeex.netcap.capture.PacketProcessor;
import com.yuanyeex.netcap.capture.PcapHandleCapture;
import org.apache.commons.cli.*;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Dns Capture and send to kafka stream bootstrap class.
 */
public class DnsCaptureMain {

    private static final Logger logger = LoggerFactory.getLogger("pcap-main");

    public static void main(String[] args) {
        logger.info("Start!");
        Properties properties = parseArgs(args);
        try {
            PacketProcessor.startProcessor();
            PcapHandleCapture.startCapture(properties);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
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
