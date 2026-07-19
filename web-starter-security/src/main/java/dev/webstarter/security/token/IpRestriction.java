package dev.webstarter.security.token;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;

public final class IpRestriction {

    private IpRestriction() {
    }

    public static boolean permits(String remoteAddress, Collection<String> cidrs) {
        if (cidrs == null || cidrs.isEmpty()) {
            return true;
        }
        if (remoteAddress == null || remoteAddress.isBlank()) {
            return false;
        }
        try {
            InetAddress candidate = parseLiteral(remoteAddress);
            return cidrs.stream().anyMatch(cidr -> contains(candidate, cidr));
        }
        catch (UnknownHostException ex) {
            return false;
        }
    }

    public static void validate(Collection<String> cidrs) {
        if (cidrs == null) {
            return;
        }
        for (String cidr : cidrs) {
            if (!validCidr(cidr)) {
                throw new IllegalArgumentException("Invalid IP CIDR: " + cidr);
            }
        }
    }

    static boolean contains(InetAddress candidate, String cidr) {
        if (cidr == null || cidr.isBlank()) {
            return false;
        }
        String[] parts = cidr.trim().split("/", 2);
        try {
            InetAddress network = parseLiteral(parts[0]);
            byte[] addressBytes = candidate.getAddress();
            byte[] networkBytes = network.getAddress();
            if (addressBytes.length != networkBytes.length) {
                return false;
            }
            int prefixLength = parts.length == 1
                    ? addressBytes.length * 8
                    : Integer.parseInt(parts[1]);
            if (prefixLength < 0 || prefixLength > addressBytes.length * 8) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            int remainder = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (addressBytes[i] != networkBytes[i]) {
                    return false;
                }
            }
            if (remainder == 0) {
                return true;
            }
            int mask = (0xff << (8 - remainder)) & 0xff;
            return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }
        catch (UnknownHostException | NumberFormatException ex) {
            return false;
        }
    }

    private static boolean validCidr(String cidr) {
        if (cidr == null || cidr.isBlank()) {
            return false;
        }
        String[] parts = cidr.trim().split("/", -1);
        if (parts.length > 2 || parts[0].isBlank()) {
            return false;
        }
        try {
            InetAddress address = parseLiteral(parts[0]);
            if (parts.length == 1) {
                return true;
            }
            int prefix = Integer.parseInt(parts[1]);
            return prefix >= 0 && prefix <= address.getAddress().length * 8;
        }
        catch (UnknownHostException | NumberFormatException exception) {
            return false;
        }
    }

    private static InetAddress parseLiteral(String value) throws UnknownHostException {
        String candidate = value == null ? "" : value.trim();
        if (candidate.indexOf(':') >= 0) {
            if (candidate.indexOf('%') >= 0) {
                throw new UnknownHostException("Scoped IPv6 addresses are not accepted");
            }
            return InetAddress.getByName(candidate);
        }
        String[] octets = candidate.split("\\.", -1);
        if (octets.length != 4) {
            throw new UnknownHostException("Address must be an IP literal");
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3 || !octet.chars().allMatch(Character::isDigit)) {
                throw new UnknownHostException("Address must be an IP literal");
            }
            int valueAsNumber = Integer.parseInt(octet);
            if (valueAsNumber > 255) {
                throw new UnknownHostException("Address must be an IP literal");
            }
        }
        return InetAddress.getByAddress(new byte[] {
                (byte) Integer.parseInt(octets[0]),
                (byte) Integer.parseInt(octets[1]),
                (byte) Integer.parseInt(octets[2]),
                (byte) Integer.parseInt(octets[3])
        });
    }
}
