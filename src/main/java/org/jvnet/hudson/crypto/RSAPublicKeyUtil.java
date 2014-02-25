package org.jvnet.hudson.crypto;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Utility code to work around horrible Java Crypto API.
 *
 * @author Kohsuke Kawaguchi
 */
public class RSAPublicKeyUtil {
    /**
     * Loads RSA public key by parsing the OpenSSH format that it uses in ~/.ssh/authorized_keys
     *
     * @throws IllegalArgumentException
     *      If the input line doesn't follow the expected format.
     */
    public static PublicKey readPublicKey(String keyLine) throws GeneralSecurityException {
        String[] tokens = keyLine.split(" ");
        if (tokens.length<2)   throw new IllegalArgumentException("Invalid public key format: "+keyLine);

        byte[] bytes = Base64.decodeBase64(tokens[1]);
        DataInputStream2 in = new DataInputStream2(new ByteArrayInputStream(bytes));

        try {
            String type = in.decodeString();
            if (type.equals("ssh-rsa")) {
                BigInteger e = in.readBigInt();
                BigInteger m = in.readBigInt();
                RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } else if (type.equals("ssh-dss")) {
                BigInteger p = in.readBigInt();
                BigInteger q = in.readBigInt();
                BigInteger g = in.readBigInt();
                BigInteger y = in.readBigInt();
                DSAPublicKeySpec spec = new DSAPublicKeySpec(y, p, q, g);
                return KeyFactory.getInstance("DSA").generatePublic(spec);
            } else {
                throw new IllegalArgumentException("unknown type " + type);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid public key format: "+keyLine,e);
        }
    }

    static class DataInputStream2 extends DataInputStream {
        DataInputStream2(InputStream in) {
            super(in);
        }

        public String decodeString() throws IOException {
            int len = readInt();
            byte[] buf = new byte[len];
            readFully(buf);
            return new String(buf);
        }

        private BigInteger readBigInt() throws IOException {
            int len = readInt();
            byte[] buf = new byte[len];
            readFully(buf);
            return new BigInteger(buf);
        }
    }
}
