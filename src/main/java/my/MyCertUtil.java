package my;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.zz.gmhelper.cert.SM2CertUtil;

/**
 *
 * @author realwronger
 */
public class MyCertUtil {

    static String FOLDER_PATH = "instCert";

    static String CERT_PATH   = "xxxx.cer";
    static String CERT_PATH2  = "0000.cer";

    public static void main(String[] args) throws IOException, CertificateException,
                                           NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //        File file = new File(CERT_PATH2);
        //        X509Certificate cert = parseStringCert(file);
        //        print(cert);

        File file = new File(FOLDER_PATH);
        for (File certFile : file.listFiles()) {
            X509Certificate cert = parseStringCert(certFile);
            String fileName = certFile.getName();
            String notBefore = new DateTime(cert.getNotBefore()).toString("yyyy-MM-dd HH:mm:ss");
            String notAfter = new DateTime(cert.getNotAfter()).toString("yyyy-MM-dd HH:mm:ss");
            System.out.println(String.format("%s,%s,%s", fileName, notBefore, notAfter));
        }
    }

    static void print(X509Certificate cert) {
        System.out.println(
            "Not Before: " + new DateTime(cert.getNotBefore()).toString("yyyy-MM-dd HH:mm:ss"));
        System.out.println(
            "Not After : " + new DateTime(cert.getNotAfter()).toString("yyyy-MM-dd HH:mm:ss"));
    }

    static X509Certificate parseCert(File certFile) {
        try (InputStream istream = new FileInputStream(certFile)) {
            return SM2CertUtil.getX509Certificate(istream);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    static X509Certificate parseStringCert(File certFile) {
        try {
            byte[] certBytes = Files.readAllBytes(Paths.get(certFile.getAbsolutePath()));
            String cert = new String(certBytes, "UTF-8");
            cert = "-----BEGIN CERTIFICATE-----\r\n" + cert + "\r\n-----END CERTIFICATE-----";
            return SM2CertUtil.getX509Certificate(cert.getBytes());
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

}
