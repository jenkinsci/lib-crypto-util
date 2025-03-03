package org.jvnet.hudson.crypto;

import static org.junit.Assert.assertThrows;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * @author Kohsuke Kawaguchi
 */
public class PKIXTest {
    /**
     * Makes sure valid certificate chain validates.
     */
    @Test
    public void testPathValidation() throws Exception {
        X509Certificate site = load("site.crt");
        X509Certificate sun = load("sun.crt");
        X509Certificate verisign = load("verisign.crt");

        // if this test fails because certificates expire, see get-cert.sh
        CertificateUtil.validatePath(Arrays.asList(site, sun));

        // invalid order
        assertThrows(
                CertPathValidatorException.class,
                () -> CertificateUtil.validatePath(Arrays.asList(sun, site)));

        // missing link
        assertThrows(
                CertPathValidatorException.class,
                () -> CertificateUtil.validatePath(List.of(site)));
    }

    private X509Certificate load(String res) throws GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(getClass().getResourceAsStream(res));
    }

//    private static void test1() throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException, CertPathBuilderException {
//        X509Certificate verisign = loadCertificate(new FileInputStream("/home/kohsuke/Desktop/VerisignClass3PublicPrimaryCertificationAuthority-G2.crt"));
//        X509Certificate sun = loadCertificate(new FileInputStream("/home/kohsuke/Desktop/SunMicrosystemsIncSSLCA.crt"));
//        X509Certificate cert = loadCertificate(new FileInputStream("/home/kohsuke/Desktop/identity.sun.com.crt"));
//        CertStore cs = CertStore.getInstance("Collection",new CollectionCertStoreParameters(Arrays.asList(sun,verisign)));
//
//
//        KeyStore ks = KeyStore.getInstance("JKS");
//        ks.load(null);
//        ks.setCertificateEntry("root", verisign);
//        ks.setCertificateEntry("root2", sun);
//
//        X509CertSelector target = new X509CertSelector();
//        target.setCertificate(cert);
//        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
//        PKIXBuilderParameters params = new PKIXBuilderParameters(ks,target);
//        params.setCertStores(Arrays.asList(cs));
//        CertPathBuilderResult result = builder.build(params);
//        System.out.println(result);
//        result.getCertPath().getEncoded();
//    }

//    private static X509Certificate loadCertificate(FileInputStream src) throws CertificateException, FileNotFoundException {
//        return (X509Certificate) CertificateFactory.getInstance("X.509")
//                .generateCertificate(src);
//    }
}
