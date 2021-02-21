package il.ac.idc.cs.sinkhole;

import java.net.*;
import java.util.*;
import java.io.*;

public class SinkholeServer {

    static final int USAGE_ERROR_EXIT = 1;
    static final int DNS_PORT = 53;
    static final int DEFAULT_PORT = 5300;
    static final int MAX_MSG_SIZE_DNS = 1024;
    static final int MAX_ROUNDS = 16;
    static DatagramSocket serverSocket;
    static HashSet<String> blockList;

    public static void main(String[] args){
        blockList = new HashSet<>();

        if (args.length > 1) {
            System.err.println("Usage: SinkholeServer [blacklist.txt]");
            System.exit(USAGE_ERROR_EXIT);
        }
        if (args.length > 0) {
            importBlockList(args[0]);
        }

        try {
            serverSocket = new DatagramSocket(DEFAULT_PORT);
            while (true) {
                run();
            }
        } catch (SocketException se) {
            System.err.printf("Port %d unavailable.%n", DEFAULT_PORT);
        } finally {
            serverSocket.close();
        }
    }

    private static void run() throws SocketException{
        try {
            DatagramPacket receivePacket = new DatagramPacket(new byte[MAX_MSG_SIZE_DNS], MAX_MSG_SIZE_DNS);
            serverSocket.receive(receivePacket);

            // Save Client Info
            InetAddress clientAddress = receivePacket.getAddress();
            int clientPort = receivePacket.getPort();
            byte[] dataCopy = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());
            String domainName = getDomainName(dataCopy, 12);

            // Check Block list
            if (blockList.contains(domainName)) {
                // Flags edit
                dataCopy[2] |= (byte)0x81; // QR and RD
                dataCopy[3] |= (byte)0x83; // RA and RCODE

                // Send NX DOMAIN Packet
                DatagramPacket sendPacketError = new DatagramPacket(dataCopy, dataCopy.length, clientAddress, clientPort);
                serverSocket.send(sendPacketError);

                System.err.println("Domain blocked.");
                return;
            }

            // Send packet to root server
            InetAddress RootServerAddress = InetAddress.getByName(getRandomRootServer());
            DatagramPacket sendPacket = new DatagramPacket(dataCopy, dataCopy.length, RootServerAddress, DNS_PORT);
            serverSocket.send(sendPacket);

            // Receive response
            serverSocket.receive(receivePacket);
            byte[] receiveData = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());

            int roundsCount = 0;

            while (queryConditions(receiveData) && roundsCount < MAX_ROUNDS) {

                // Get next server address
                int answerIndex = GetAnswerIndex(receiveData);
                String serverName = getDomainName(receiveData, answerIndex);
                InetAddress serverAddress = InetAddress.getByName(serverName);

                // Send query to new server
                DatagramPacket sendPacketFinal = new DatagramPacket(sendPacket.getData(), sendPacket.getLength(), serverAddress, DNS_PORT);
                serverSocket.send(sendPacketFinal);

                // Receive response
                serverSocket.receive(receivePacket);
                receiveData = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());

                // Increase round count
                roundsCount++;
            }

            // Flags edit
            receiveData[2] |= (byte)0x80; // QR
            receiveData[2] &= (byte)0xfb; // RD
            receiveData[3] |= (byte)0x80; // RA

            // Send Response packet
            sendPacket = new DatagramPacket(receiveData, receiveData.length, clientAddress, clientPort);
            serverSocket.send(sendPacket);

        } catch (UnknownHostException uhe) {
            System.err.println("Requested address unavailable.");
        } catch (IOException ioe) {
            System.err.println("Send/Receive packet error");
        } catch (Exception e) {
            System.err.println("Error encountered.");
        }
    }

    private static int GetAnswerIndex(byte[] i_Data) {
        int i = 12; // Skip HEADER

        while (i_Data[i] != 0) { // Skip labels
            i++;
        }
        i += 17; // Hand counted bytes to skip

        return i;
    }

    private static boolean queryConditions(byte[] i_Data) {
        // Get Flags to validate conditions
        int responseCode = i_Data[3]; // RCODE
        int numOfAnswers = (i_Data[6] << 8) | i_Data[7]; // ANCOUNT
        int numOfAuthorities = (i_Data[8] << 8) | i_Data[9]; // NSCOUNT

        return responseCode == 0 && numOfAnswers == 0 && numOfAuthorities > 0;
    }

    private static String getRandomRootServer() {
        int count = 13; // 13 root servers [a-m]
        String[] rootServers = new String[count];

        for (int i = 0; i < count; i++) {
            rootServers[i] = String.format("%c.root-servers.net", (char)('a' + i));
        }

        int randIndex = new Random().nextInt(rootServers.length);
        return rootServers[randIndex];
    }

    private static String getDomainName(byte[] i_Data, int i_Index) {
        StringBuilder domainName = new StringBuilder();

        while (i_Data[i_Index] != 0) { // 0 -> end label
            int len = i_Data[i_Index] & 0xff; // Unsigned short

            while ((len & 0xc0) == 0xc0) { // Check compression recursively
                i_Index = i_Data[i_Index + 1];
                len = i_Data[i_Index] & 0xff; // Unsigned short
            }

            i_Index++;

            for (int i = 0; i < len; i++) {
                domainName.append((char) (int) i_Data[i_Index + i]);
            }

            domainName.append(".");
            i_Index += len;
        }

        return domainName.substring(0, domainName.length() - 1); // To ignore last dot
    }

    private static void importBlockList(String i_filePath) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(i_filePath));
            String line;

            while ((line = br.readLine()) != null) {
                blockList.add(line);
            }
        } catch (Exception ex) {
            System.err.println("Unable to read block list file");
        }
    }
}
