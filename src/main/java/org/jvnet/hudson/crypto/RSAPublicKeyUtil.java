package org.jvnet.hudson.crypto;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
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

    static class DataOutputStream2 extends DataOutputStream {
        DataOutputStream2(OutputStream out) {
            super(out);
        }

        public void writeString(String s) throws IOException {
            writeBinary(s.getBytes());
        }

        public void writeBinary(byte[] buf) throws IOException {
            writeInt(buf.length);
            write(buf);
        }

        private void writeBigInt(BigInteger i) throws IOException {
            writeBinary(i.toByteArray());
        }
    }

    /**
     * Gets RSA key fingerprint in the form of "f7:7a:42:76:79:e8:8a:1a:4a:32:0c:b3:f9:3b:53:d4"
     */
    public static String getFingerPrint(PublicKey key) throws GeneralSecurityException {
        byte[] extractedBytes =  encode(key);
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(extractedBytes);
        return toHex(digest);
    }

    /**
     * Gets RSA key fingerprint in the form EC2 does, which is different from how OpenSSH does.
     */
    public static String getEC2FingerPrint(Key publicKey) throws GeneralSecurityException {
        byte[] extractedBytes =  publicKey.getEncoded();
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(extractedBytes);
        return toHex(digest);
    }

    /**
     * Encodes bytes into the form of "f7:7a:42:76:79:e8:8a:1a:4a:32:0c:b3:f9:3b:53:d4"
     */
    private static String toHex(byte[] digest) {
        String str = Hex.encodeHexString(digest);

        // insert ";"
        StringBuilder buf = new StringBuilder(digest.length*3);
        for (int i=0; i<str.length(); i+=2) {
            if (buf.length()>0) buf.append(':');
            buf.append(str,i,i+2);
        }

        return buf.toString();
    }

    /**
     * Encodes RSA/DSA public keys into the OpenSSH format.
     */
    public static byte[] encode(PublicKey key) throws GeneralSecurityException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream2 out = new DataOutputStream2(baos);

            if (key instanceof RSAPublicKey) {
                RSAPublicKeySpec spec = KeyFactory.getInstance("RSA").getKeySpec(key, RSAPublicKeySpec.class);

                out.writeString("ssh-rsa");
                out.writeBigInt(spec.getPublicExponent());
                out.writeBigInt(spec.getModulus());

                return baos.toByteArray();
            }

            if (key instanceof DSAPublicKey) {
                DSAPublicKeySpec dsaspec = KeyFactory.getInstance("DSA").getKeySpec(key, DSAPublicKeySpec.class);

                out.writeString("ssh-dss");
                out.writeBigInt(dsaspec.getP());
                out.writeBigInt(dsaspec.getQ());
                out.writeBigInt(dsaspec.getG());
                out.writeBigInt(dsaspec.getY());

                return baos.toByteArray();
            }

            throw new IllegalArgumentException("Unexpected key type: "+key);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
