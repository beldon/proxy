package beldon.proxy.crt;

import org.bouncycastle.asn1.x509.Certificate;
import org.junit.Assert;
import org.junit.Test;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import java.io.*;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertGeneratorTest {

    private static final String DN_ZHANGSAN = "CN=www.baidu.com,OU=Beldon,O=Beldon,L=ShenZhen,ST=GuangDong,C=CN";
    private static final String DN_CA = "CN=BeldonLearn,OU=Beldon,O=Beldon,L=GuangZou,ST=GuangDong,C=CN";
    private CertGenerator certGenerator = new DefaultCertGenerator();

    private static final String ROOT_PATH = "src/main/resources";
    private static final String CA_FILE_NAME = "ca.crt";
    private static final String CA_PRIVATE_FILE_NAME = "ca_private.der";

    @Test
    public void verifyRootCert() throws Exception {
        KeyPair keyPair = certGenerator.generateKeyPair();
        Certificate ca = certGenerator.generateCA(keyPair.getPrivate(), keyPair.getPublic(), "SHA1withRSA", DN_CA, 100 * 24 * 60 * 60 * 1000L);
        byte[] encoded = ca.getEncoded();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inStream);
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initVerify(certificate);
        signature.update(certificate.getTBSCertificate());
        Assert.assertTrue(signature.verify(certificate.getSignature()));
    }

    @Test
    public void verifyCert() throws Exception {
        KeyPair rootKeyPair = certGenerator.generateKeyPair();
        Certificate ca = certGenerator.generateCA(rootKeyPair.getPrivate(), rootKeyPair.getPublic(), "SHA256withRSA", DN_CA, 100 * 24 * 60 * 60 * 1000L);
        byte[] encoded = ca.getEncoded();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(inStream);


        KeyPair clientKeyPair = certGenerator.generateKeyPair();

        Date notAfter = new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000L);
        Date notBefore = new Date();

        X509Certificate clientCert = certGenerator.generateCert(rootKeyPair.getPrivate(), clientKeyPair.getPublic(),
                "SHA1withRSA", DN_CA, DN_ZHANGSAN, notBefore, notAfter);

        Signature signature = Signature.getInstance(clientCert.getSigAlgName());
        signature.initVerify(rootCert.getPublicKey());
        signature.update(clientCert.getTBSCertificate());
        Assert.assertTrue(signature.verify(clientCert.getSignature()));


    }

    @Test
    public void verifyCert2() throws Exception {
        KeyPair rootKeyPair = certGenerator.generateKeyPair();
        Certificate ca = certGenerator.generateCA(rootKeyPair.getPrivate(), rootKeyPair.getPublic(), "SHA256withRSA", DN_CA, 100 * 24 * 60 * 60 * 1000L);
        byte[] encoded = ca.getEncoded();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(inStream);


        KeyPair clientKeyPair = certGenerator.generateKeyPair();

        Date notAfter = new Date(System.currentTimeMillis() + 100 * 24 * 60 * 60 * 1000L);
        Date notBefore = new Date();

        String host = "www.baidu.com";
        String subject = "C=CN, ST=GD, L=SZ, O=lee, OU=study, CN=" + host;
        X509Certificate clientCert = certGenerator.generateCert(rootKeyPair.getPrivate(), rootKeyPair.getPublic(), "SHA256WithRSAEncryption", DN_CA, subject, notBefore, notAfter, host);

        Signature signature2 = Signature.getInstance(clientCert.getSigAlgName());
        signature2.initVerify(rootCert.getPublicKey());
        signature2.update(clientCert.getTBSCertificate());
        Assert.assertTrue(signature2.verify(clientCert.getSignature()));
    }

    //    @Test
    public void printCA() throws Exception {
        KeyPair keyPair = certGenerator.generateKeyPair();
        Certificate ca = certGenerator.generateCA(keyPair.getPrivate(), keyPair.getPublic(), "SHA1withRSA", DN_CA, 100 * 24 * 60 * 60 * 1000L);
        byte[] encoded = ca.getEncoded();
        BASE64Encoder encoder = new BASE64Encoder();
        System.out.println(X509Factory.BEGIN_CERT);
        encoder.encodeBuffer(encoded, System.out);
        System.out.println(X509Factory.END_CERT);
    }

    @Test
    public void writeCA() throws Exception {
        File root = new File(ROOT_PATH);
        File caFile = new File(root, CA_FILE_NAME);
        File caPriFile = new File(root, CA_PRIVATE_FILE_NAME);
        KeyPair keyPair = certGenerator.generateKeyPair();
        Certificate ca = certGenerator.generateCA(keyPair.getPrivate(), keyPair.getPublic(), "SHA256withRSA", DN_CA, 100 * 24 * 60 * 60 * 1000L);
        byte[] encoded = ca.getEncoded();
        new FileOutputStream(caFile).write(encoded);
        new FileOutputStream(caPriFile).write(keyPair.getPrivate().getEncoded());
//        BASE64Encoder encoder = new BASE64Encoder();
//        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(caFile));
//        bos.write(X509Factory.BEGIN_CERT.getBytes());
//        bos.write("\n".getBytes());
//        encoder.encodeBuffer(encoded, bos);
//        bos.write(X509Factory.END_CERT.getBytes());
    }
}